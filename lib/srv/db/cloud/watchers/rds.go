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

package watchers

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/aws/aws-sdk-go/service/rds/rdsiface"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/teleport/lib/utils"
)

// rdsFetcherConfig is the RDS databases fetcher configuration.
type rdsFetcherConfig struct {
	// Labels is a selector to match cloud databases.
	Labels types.Labels
	// RDS is the RDS API client.
	RDS rdsiface.RDSAPI
	// Region is the AWS region to query databases in.
	Region string
}

// CheckAndSetDefaults validates the config and sets defaults.
func (c *rdsFetcherConfig) CheckAndSetDefaults() error {
	if len(c.Labels) == 0 {
		return trace.BadParameter("missing parameter Labels")
	}
	if c.RDS == nil {
		return trace.BadParameter("missing parameter RDS")
	}
	if c.Region == "" {
		return trace.BadParameter("missing parameter Region")
	}
	return nil
}

// rdsDBInstancesFetcher retrieves RDS DB instances.
type rdsDBInstancesFetcher struct {
	cfg rdsFetcherConfig
	log logrus.FieldLogger
}

// newRDSDBInstancesFetcher returns a new RDS DB instances fetcher instance.
func newRDSDBInstancesFetcher(config rdsFetcherConfig) (Fetcher, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &rdsDBInstancesFetcher{
		cfg: config,
		log: logrus.WithFields(logrus.Fields{
			trace.Component: "watch:rds",
			"labels":        config.Labels,
			"region":        config.Region,
		}),
	}, nil
}

// Get returns RDS DB instances matching the watcher's selectors.
func (f *rdsDBInstancesFetcher) Get(ctx context.Context) (types.Databases, error) {
	rdsDatabases, err := f.getRDSDatabases(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return filterDatabasesByLabels(rdsDatabases, f.cfg.Labels, f.log), nil
}

// getRDSDatabases returns a list of database resources representing RDS instances.
func (f *rdsDBInstancesFetcher) getRDSDatabases(ctx context.Context) (types.Databases, error) {
	instances, err := getAllDBInstances(ctx, f.cfg.RDS, common.MaxPages, false)
	if common.IsUnrecognizedAWSEngineNameError(err) {
		f.log.WithError(err).Warn("Teleport supports an engine which is unrecognized in this AWS region. Querying engine versions.")
		// fallback to describe only instances with recognized engines in the AWS region.
		instances, err = getAllDBInstances(ctx, f.cfg.RDS, common.MaxPages, true)
	}
	if err != nil {
		return nil, common.ConvertError(err)
	}
	databases := make(types.Databases, 0, len(instances))
	for _, instance := range instances {
		if !services.IsRDSInstanceSupported(instance) {
			f.log.Debugf("RDS instance %q (engine mode %v, engine version %v) doesn't support IAM authentication. Skipping.",
				aws.StringValue(instance.DBInstanceIdentifier),
				aws.StringValue(instance.Engine),
				aws.StringValue(instance.EngineVersion))
			continue
		}

		if !services.IsRDSInstanceAvailable(instance) {
			f.log.Debugf("The current status of RDS instance %q is %q. Skipping.",
				aws.StringValue(instance.DBInstanceIdentifier),
				aws.StringValue(instance.DBInstanceStatus))
			continue
		}

		database, err := services.NewDatabaseFromRDSInstance(instance)
		if err != nil {
			f.log.Warnf("Could not convert RDS instance %q to database resource: %v.",
				aws.StringValue(instance.DBInstanceIdentifier), err)
		} else {
			databases = append(databases, database)
		}
	}
	return databases, nil
}

// getAllDBInstances fetches all RDS instances using the provided client, up
// to the specified max number of pages.
func getAllDBInstances(ctx context.Context, rdsClient rdsiface.RDSAPI, maxPages int, checkFilters bool) (instances []*rds.DBInstance, err error) {
	filters, err := rdsFilters(ctx, rdsClient, checkFilters, maxPages)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var pageNum int
	err = rdsClient.DescribeDBInstancesPagesWithContext(ctx, &rds.DescribeDBInstancesInput{
		Filters: filters,
	}, func(ddo *rds.DescribeDBInstancesOutput, lastPage bool) bool {
		pageNum++
		instances = append(instances, ddo.DBInstances...)
		return pageNum <= maxPages
	})
	return instances, trace.Wrap(err)
}

// String returns the fetcher's string description.
func (f *rdsDBInstancesFetcher) String() string {
	return fmt.Sprintf("rdsDBInstancesFetcher(Region=%v, Labels=%v)",
		f.cfg.Region, f.cfg.Labels)
}

// rdsAuroraClustersFetcher retrieves RDS Aurora clusters.
type rdsAuroraClustersFetcher struct {
	cfg rdsFetcherConfig
	log logrus.FieldLogger
}

// newRDSAuroraClustersFetcher returns a new RDS Aurora fetcher instance.
func newRDSAuroraClustersFetcher(config rdsFetcherConfig) (Fetcher, error) {
	if err := config.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &rdsAuroraClustersFetcher{
		cfg: config,
		log: logrus.WithFields(logrus.Fields{
			trace.Component: "watch:aurora",
			"labels":        config.Labels,
			"region":        config.Region,
		}),
	}, nil
}

// Get returns Aurora clusters matching the watcher's selectors.
func (f *rdsAuroraClustersFetcher) Get(ctx context.Context) (types.Databases, error) {
	auroraDatabases, err := f.getAuroraDatabases(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	return filterDatabasesByLabels(auroraDatabases, f.cfg.Labels, f.log), nil
}

// getAuroraDatabases returns a list of database resources representing RDS clusters.
func (f *rdsAuroraClustersFetcher) getAuroraDatabases(ctx context.Context) (types.Databases, error) {
	clusters, err := getAllDBClusters(ctx, f.cfg.RDS, common.MaxPages, false)
	if common.IsUnrecognizedAWSEngineNameError(err) {
		f.log.WithError(err).Warn("Teleport supports an engine which is unrecognized in this AWS region. Querying engine versions.")
		// fallback to try to describe only clusters with engines recognized in the AWS region.
		clusters, err = getAllDBClusters(ctx, f.cfg.RDS, common.MaxPages, true)
	}
	if err != nil {
		return nil, common.ConvertError(err)
	}
	databases := make(types.Databases, 0, len(clusters))
	for _, cluster := range clusters {
		if !services.IsRDSClusterSupported(cluster) {
			f.log.Debugf("Aurora cluster %q (engine mode %v, engine version %v) doesn't support IAM authentication. Skipping.",
				aws.StringValue(cluster.DBClusterIdentifier),
				aws.StringValue(cluster.EngineMode),
				aws.StringValue(cluster.EngineVersion))
			continue
		}

		if !services.IsRDSClusterAvailable(cluster) {
			f.log.Debugf("The current status of Aurora cluster %q is %q. Skipping.",
				aws.StringValue(cluster.DBClusterIdentifier),
				aws.StringValue(cluster.Status))
			continue
		}

		// Find out what types of instances the cluster has. Some examples:
		// - Aurora cluster with one instance: one writer
		// - Aurora cluster with three instances: one writer and two readers
		// - Secondary cluster of a global database: one or more readers
		var hasWriterInstance, hasReaderInstance bool
		for _, clusterMember := range cluster.DBClusterMembers {
			if clusterMember != nil {
				if aws.BoolValue(clusterMember.IsClusterWriter) {
					hasWriterInstance = true
				} else {
					hasReaderInstance = true
				}
			}
		}

		// Add a database from primary endpoint, if any writer instances.
		if cluster.Endpoint != nil && hasWriterInstance {
			database, err := services.NewDatabaseFromRDSCluster(cluster)
			if err != nil {
				f.log.Warnf("Could not convert RDS cluster %q to database resource: %v.",
					aws.StringValue(cluster.DBClusterIdentifier), err)
			} else {
				databases = append(databases, database)
			}
		}

		// Add a database from reader endpoint, if any reader instances.
		// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.Overview.Endpoints.html#Aurora.Endpoints.Reader
		if cluster.ReaderEndpoint != nil && hasReaderInstance {
			database, err := services.NewDatabaseFromRDSClusterReaderEndpoint(cluster)
			if err != nil {
				f.log.Warnf("Could not convert RDS cluster %q reader endpoint to database resource: %v.",
					aws.StringValue(cluster.DBClusterIdentifier), err)
			} else {
				databases = append(databases, database)
			}
		}

		// Add databases from custom endpoints
		if len(cluster.CustomEndpoints) > 0 {
			customEndpointDatabases, err := services.NewDatabasesFromRDSClusterCustomEndpoints(cluster)
			if err != nil {
				f.log.Warnf("Could not convert RDS cluster %q custom endpoints to database resources: %v.",
					aws.StringValue(cluster.DBClusterIdentifier), err)
			}

			databases = append(databases, customEndpointDatabases...)
		}
	}
	return databases, nil
}

// getAllDBClusters fetches all RDS clusters using the provided client, up to
// the specified max number of pages.
func getAllDBClusters(ctx context.Context, rdsClient rdsiface.RDSAPI, maxPages int, checkFilters bool) (clusters []*rds.DBCluster, err error) {
	filters, err := auroraFilters(ctx, rdsClient, checkFilters, maxPages)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var pageNum int
	err = rdsClient.DescribeDBClustersPagesWithContext(ctx, &rds.DescribeDBClustersInput{
		Filters: filters,
	}, func(ddo *rds.DescribeDBClustersOutput, lastPage bool) bool {
		pageNum++
		clusters = append(clusters, ddo.DBClusters...)
		return pageNum <= maxPages
	})
	return clusters, trace.Wrap(err)
}

// String returns the fetcher's string description.
func (f *rdsAuroraClustersFetcher) String() string {
	return fmt.Sprintf("rdsAuroraClustersFetcher(Region=%v, Labels=%v)",
		f.cfg.Region, f.cfg.Labels)
}

// rdsFilters returns filters to make sure DescribeDBInstances call returns
// only databases with engines Teleport supports.
func rdsFilters(ctx context.Context, rdsClient rdsiface.RDSAPI, checkFilters bool, maxPages int) ([]*rds.Filter, error) {
	supportedEngines := []string{
		services.RDSEnginePostgres,
		services.RDSEngineMySQL,
		services.RDSEngineMariaDB,
	}
	if !checkFilters {
		return []*rds.Filter{{
			Name:   aws.String("engine"),
			Values: aws.StringSlice(supportedEngines),
		}}, nil
	}

	// filter supported engines to include only the ones recognized by AWS in this region.
	engines, err := filterByRecognizedRDSEngines(ctx, rdsClient, supportedEngines, maxPages)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return []*rds.Filter{{
		Name:   aws.String("engine"),
		Values: aws.StringSlice(engines),
	}}, nil
}

// auroraFilters returns filters to make sure DescribeDBClusters call returns
// only databases with engines Teleport supports.
func auroraFilters(ctx context.Context, rdsClient rdsiface.RDSAPI, checkFilters bool, maxPages int) ([]*rds.Filter, error) {
	supportedEngines := []string{
		services.RDSEngineAurora,
		services.RDSEngineAuroraMySQL,
		services.RDSEngineAuroraPostgres,
	}
	if !checkFilters {
		return []*rds.Filter{{
			Name:   aws.String("engine"),
			Values: aws.StringSlice(supportedEngines),
		}}, nil
	}

	// filter supported engines to include only the ones recognized by AWS in this region.
	engines, err := filterByRecognizedRDSEngines(ctx, rdsClient, supportedEngines, maxPages)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return []*rds.Filter{{
		Name:   aws.String("engine"),
		Values: aws.StringSlice(engines),
	}}, nil
}

// filterByRecognizedRDSEngines filters Teleport supported engine names to include only those recognized by AWS.
func filterByRecognizedRDSEngines(ctx context.Context, rdsClient rdsiface.RDSAPI, supportedEngines []string, maxPages int) ([]string, error) {
	recognized, err := getRecognizedRDSEngines(ctx, rdsClient, maxPages)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	// now filter for supported + recognized engine names.
	var engines []string
	for _, engine := range supportedEngines {
		if _, ok := recognized[engine]; ok {
			engines = append(engines, engine)
		}
	}
	// important that we don't return 0 engine names, as that would apply no filtering at all in AWS DescribeDBClusters/Instances calls.
	if len(engines) == 0 {
		return nil, trace.NotFound("Teleport supports engine names %v but none are recognized in this region.", supportedEngines)
	}
	return engines, nil
}

// getRecognizedRDSEngines gets all engine versions within an AWS region and builds a string set of AWS recognized engine names.
func getRecognizedRDSEngines(ctx context.Context, rdsClient rdsiface.RDSAPI, maxPages int) (map[string]struct{}, error) {
	var engines []string
	var pageNum int
	// https://docs.aws.amazon.com/sdk-for-go/api/service/rds/#RDS.DescribeDBEngineVersionsPages
	err := rdsClient.DescribeDBEngineVersionsPagesWithContext(ctx, &rds.DescribeDBEngineVersionsInput{},
		func(out *rds.DescribeDBEngineVersionsOutput, lastPage bool) bool {
			pageNum++
			if out.DBEngineVersions != nil {
				for _, e := range out.DBEngineVersions {
					if e == nil {
						continue
					}
					engines = append(engines, aws.StringValue(e.Engine))
				}
			}
			return pageNum <= maxPages
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return utils.StringsSet(engines), nil
}
