/*
Copyright 2021 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package aws

import (
	"bytes"
	"io"
	"net/http"

	"github.com/gravitational/oxy/forward"
	oxyutils "github.com/gravitational/oxy/utils"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/srv/app/common"
	awsutils "github.com/gravitational/teleport/lib/utils/aws"
)

type awsSignerHandler struct {
	fwd *forward.Forwarder
	AwsSignerHandlerConfig
}

type AwsSignerHandlerConfig struct {
	Log logrus.FieldLogger
	// RoundTripper is an http.RoundTripper instance used for requests.
	RoundTripper http.RoundTripper
	*awsutils.SigningService
	*common.SessionContext
}

func (cfg *AwsSignerHandlerConfig) CheckAndSetDefaults() error {
	if cfg.SigningService == nil {
		return trace.BadParameter("missing SigningService")
	}
	if cfg.SessionContext == nil {
		return trace.BadParameter("missing SessionContext")
	}
	if err := cfg.SessionContext.Check(); err != nil {
		return trace.Wrap(err)
	}
	if cfg.RoundTripper == nil {
		tr, err := defaults.Transport()
		if err != nil {
			return trace.Wrap(err)
		}
		cfg.RoundTripper = tr
	}
	if cfg.Log == nil {
		cfg.Log = logrus.WithField(trace.Component, "aws:signer")
	}
	return nil
}

func NewAWSSignerHandler(config AwsSignerHandlerConfig) (http.Handler, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}

	handler := &awsSignerHandler{
		AwsSignerHandlerConfig: config,
	}
	fwd, err := forward.New(
		forward.RoundTripper(config.RoundTripper),
		forward.ErrorHandler(oxyutils.ErrorHandlerFunc(handler.formatForwardResponseError)),
		forward.PassHostHeader(true),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	handler.fwd = fwd
	return handler, nil
}

func (s *awsSignerHandler) formatForwardResponseError(rw http.ResponseWriter, r *http.Request, err error) {
	// Convert trace error type to HTTP and write response.
	code := trace.ErrorToCode(err)
	s.Log.WithError(err).Debugf("Failed to process request. Response status code: %v.", code)
	rw.WriteHeader(code)
}

// ServeHTTP handles incoming requests and forwards them to the proper AWS API.
// Handling steps:
// 1) Decode Authorization Header. Authorization Header example:
//
//		Authorization: AWS4-HMAC-SHA256
//		Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
//		SignedHeaders=host;range;x-amz-date,
//		Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
//
//	 2. Extract credential section from credential Authorization Header.
//	 3. Extract aws-region and aws-service from the credential section.
//	 4. Build AWS API endpoint based on extracted aws-region and aws-service fields.
//	    Not that for endpoint resolving the https://github.com/aws/aws-sdk-go/aws/endpoints/endpoints.go
//	    package is used and when Amazon releases a new API the dependency update is needed.
//	 5. Sign HTTP request.
//	 6. Forward the signed HTTP request to the AWS API.
func (s *awsSignerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	signedReq, payload, endpoint, err := s.SignRequest(r,
		awsutils.SigningCtx{
			Expiry:        s.Identity.Expires,
			SessionName:   s.Identity.Username,
			AWSRoleArn:    s.Identity.RouteToApp.AWSRoleARN,
			AWSExternalID: s.App.GetAWSExternalID(),
		})
	if err != nil {
		s.formatForwardResponseError(w, r, err)
		return
	}
	recorder := httplib.NewResponseStatusRecorder(w)
	s.fwd.ServeHTTP(recorder, signedReq)
	// emit audit event with original request, but change the URL since we resolved and rewrote it.
	signedReq.Body = io.NopCloser(bytes.NewReader(payload))
	if awsutils.IsDynamoDBEndpoint(endpoint) {
		err = s.Audit.OnDynamoDBRequest(r.Context(), s.SessionContext, signedReq, recorder.Status(), endpoint)
	} else {
		err = s.Audit.OnRequest(r.Context(), s.SessionContext, signedReq, recorder.Status(), endpoint)
	}
	if err != nil {
		s.Log.WithError(err).Warn("Failed to emit audit event.")
	}
}
