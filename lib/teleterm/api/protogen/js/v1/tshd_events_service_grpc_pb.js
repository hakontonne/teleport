// GENERATED CODE -- DO NOT EDIT!

// Original file comments:
// Copyright 2022 Gravitational, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
'use strict';
var grpc = require('@grpc/grpc-js');
var v1_tshd_events_service_pb = require('../v1/tshd_events_service_pb.js');

function serialize_teleport_terminal_v1_ReloginRequiredRequest(arg) {
  if (!(arg instanceof v1_tshd_events_service_pb.ReloginRequiredRequest)) {
    throw new Error('Expected argument of type teleport.terminal.v1.ReloginRequiredRequest');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_terminal_v1_ReloginRequiredRequest(buffer_arg) {
  return v1_tshd_events_service_pb.ReloginRequiredRequest.deserializeBinary(new Uint8Array(buffer_arg));
}

function serialize_teleport_terminal_v1_ReloginRequiredResponse(arg) {
  if (!(arg instanceof v1_tshd_events_service_pb.ReloginRequiredResponse)) {
    throw new Error('Expected argument of type teleport.terminal.v1.ReloginRequiredResponse');
  }
  return Buffer.from(arg.serializeBinary());
}

function deserialize_teleport_terminal_v1_ReloginRequiredResponse(buffer_arg) {
  return v1_tshd_events_service_pb.ReloginRequiredResponse.deserializeBinary(new Uint8Array(buffer_arg));
}


// TshdEventsService is served by the Electron app. The tsh daemon calls this service to notify the
// app about actions that happen outside of the app itself. For example, when the user tries to
// connect to a gateway served by the daemon but the cert has since expired and needs to be
// reissued.
var TshdEventsServiceService = exports.TshdEventsServiceService = {
  // TODO: Add comment.
reloginRequired: {
    path: '/teleport.terminal.v1.TshdEventsService/ReloginRequired',
    requestStream: false,
    responseStream: false,
    requestType: v1_tshd_events_service_pb.ReloginRequiredRequest,
    responseType: v1_tshd_events_service_pb.ReloginRequiredResponse,
    requestSerialize: serialize_teleport_terminal_v1_ReloginRequiredRequest,
    requestDeserialize: deserialize_teleport_terminal_v1_ReloginRequiredRequest,
    responseSerialize: serialize_teleport_terminal_v1_ReloginRequiredResponse,
    responseDeserialize: deserialize_teleport_terminal_v1_ReloginRequiredResponse,
  },
};

exports.TshdEventsServiceClient = grpc.makeGenericClientConstructor(TshdEventsServiceService);
