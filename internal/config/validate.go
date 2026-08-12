package config

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
)

// Valid enumerations. Port of the sets in fig/config/__init__.py:9-11.
var (
	// validBackendNames lists the recognized backend names. It is duplicated
	// here (rather than importing the backend registry) to avoid an import
	// cycle; keep it in sync with backend.Names().
	validBackendNames = []string{"AWS", "AWS_SQS", "AZURE", "GCP", "WORKSPACEONE", "CLOUDTRAIL_LAKE", "GENERIC"}

	validCloudRegions = []string{"us-1", "us-2", "eu-1", "us-gov-1"}

	sensorRecognizedClouds = []string{"AWS", "Azure", "GCP", "unrecognized"}
)

// malformedf builds a validation error carrying the standard
// "malformed configuration: " prefix, so every site states only its specific
// problem.
func malformedf(format string, args ...any) error {
	return fmt.Errorf("malformed configuration: "+format, args...)
}

// Validate ports every branch of validate()/validate_falcon()/validate_events()/
// validate_backends() (fig/config/__init__.py:142-238). Unlike the Python code
// (which fails on the first error), it accumulates ALL problems with
// errors.Join so the operator sees every misconfiguration at once.
func (c *Config) Validate() error {
	var errs []error

	// main
	if c.Main.WorkerThreads < 1 || c.Main.WorkerThreads > 127 {
		errs = append(errs, malformedf("expected main.worker_threads to be in range 1-127"))
	}

	errs = append(errs, c.validateFalcon()...)
	errs = append(errs, c.validateEvents()...)
	errs = append(errs, c.validateBackends()...)
	errs = append(errs, c.validateEnrich()...)

	return errors.Join(errs...)
}

// validateFalcon ports validate_falcon().
func (c *Config) validateFalcon() []error {
	var errs []error
	if c.Falcon.ReconnectRetryCount < 1 || c.Falcon.ReconnectRetryCount > 9999 {
		errs = append(errs, malformedf("expected falcon.reconnect_retry_count to be in range 1-9999"))
	}
	if !slices.Contains(validCloudRegions, c.Falcon.CloudRegion) {
		errs = append(errs, malformedf("expected falcon.cloud_region to be one of us-1, us-2, eu-1, us-gov-1, got %q", c.Falcon.CloudRegion))
	}
	return errs
}

// validateEvents ports validate_events(). Note: start_from_newest is a real
// bool here, so the Python "must be true or false" string check is unnecessary.
func (c *Config) validateEvents() []error {
	var errs []error

	for _, cloud := range c.DetectionsExcludeClouds {
		if !slices.Contains(sensorRecognizedClouds, cloud) {
			errs = append(errs, malformedf("expected events.detections_exclude_clouds to be a subset of {AWS, Azure, GCP, unrecognized}, got %q", cloud))
		}
	}

	if c.Events.SeverityThreshold < 1 || c.Events.SeverityThreshold > 5 {
		errs = append(errs, malformedf("expected events.severity_threshold to be in range 1-5"))
	}
	if c.Events.OlderThanDaysThreshold < 0 || c.Events.OlderThanDaysThreshold > 9999 {
		errs = append(errs, malformedf("expected events.older_than_days_threshold to be in range 0-9999"))
	}

	// start_from_newest XOR offset != 0.
	if c.Events.StartFromNewest && c.Events.Offset != 0 {
		errs = append(errs, malformedf("events.start_from_newest and events.offset are mutually exclusive. When start_from_newest is true, offset must be 0 (default)"))
	}

	return errs
}

// validateBackends ports validate_backends().
func (c *Config) validateBackends() []error {
	var errs []error

	if len(c.Backends) < 1 {
		errs = append(errs, malformedf("expected main.backends to contain at least one backend"))
	}
	for _, b := range c.Backends {
		if !slices.Contains(validBackendNames, b) {
			errs = append(errs, malformedf("unrecognized backend %q; expected a subset of {AWS, AWS_SQS, AZURE, GCP, WORKSPACEONE, CLOUDTRAIL_LAKE, GENERIC}", b))
		}
	}

	// requireNonEmpty appends a "<key> to be non-empty" error for each blank
	// field, matching the per-backend checks in validate_backends().
	requireNonEmpty := func(fields []struct{ key, val string }) {
		for _, f := range fields {
			if f.val == "" {
				errs = append(errs, malformedf("expected %s to be non-empty", f.key))
			}
		}
	}

	if slices.Contains(c.Backends, "AWS") {
		requireNonEmpty([]struct{ key, val string }{
			{"aws.region", c.AWS.Region},
		})
		// confirm_instance / accept_all_events are typed bools; no string check needed.
	}
	if slices.Contains(c.Backends, "AWS_SQS") {
		requireNonEmpty([]struct{ key, val string }{
			{"aws_sqs.region", c.AWSSQS.Region},
			{"aws_sqs.sqs_queue_name", c.AWSSQS.SQSQueueName},
		})
	}
	if slices.Contains(c.Backends, "WORKSPACEONE") {
		requireNonEmpty([]struct{ key, val string }{
			{"workspaceone.token", c.WorkspaceOne.Token},
			{"workspaceone.syslog_host", c.WorkspaceOne.SyslogHost},
		})
		if c.WorkspaceOne.SyslogPort < 1 || c.WorkspaceOne.SyslogPort > 65534 {
			errs = append(errs, malformedf("expected workspaceone.syslog_port to be in range 1-65534"))
		}
	}
	if slices.Contains(c.Backends, "CLOUDTRAIL_LAKE") {
		requireNonEmpty([]struct{ key, val string }{
			{"cloudtrail_lake.channel_arn", c.CloudTrailLake.ChannelARN},
			{"cloudtrail_lake.region", c.CloudTrailLake.Region},
		})
	}
	if slices.Contains(c.Backends, "AZURE") {
		errs = append(errs, c.validateAzure()...)
	}

	return errs
}

// validateEnrich bounds the enrichment caches: cache_size must be a sane
// positive capacity and cache_ttl must parse to a non-negative duration.
func (c *Config) validateEnrich() []error {
	var errs []error
	if c.Enrich.CacheSize < 1 || c.Enrich.CacheSize > 1_000_000 {
		errs = append(errs, malformedf("expected enrich.cache_size to be in range 1-1000000"))
	}
	d, err := time.ParseDuration(c.Enrich.CacheTTL)
	switch {
	case err != nil:
		errs = append(errs, malformedf("expected enrich.cache_ttl to be a valid duration (e.g. 1h, 30m), got %q", c.Enrich.CacheTTL))
	case d < 0:
		errs = append(errs, malformedf("expected enrich.cache_ttl to be non-negative, got %q", c.Enrich.CacheTTL))
	}
	return errs
}

// validateAzure ports the AZURE branch, covering the three auth methods.
func (c *Config) validateAzure() []error {
	var errs []error
	switch c.Azure.AuthMethod {
	case "legacy":
		if c.Azure.WorkspaceID == "" {
			errs = append(errs, malformedf("expected azure.workspace_id to be non-empty"))
		}
		if c.Azure.PrimaryKey == "" {
			errs = append(errs, malformedf("expected azure.primary_key to be non-empty"))
		}
	case "client_secret":
		for _, f := range []struct{ name, val string }{
			{"tenant_id", c.Azure.TenantID},
			{"client_id", c.Azure.ClientID},
			{"client_secret", c.Azure.ClientSecret},
			{"dcr_endpoint", c.Azure.DCREndpoint},
			{"dcr_immutable_id", c.Azure.DCRImmutableID},
		} {
			if f.val == "" {
				errs = append(errs, malformedf("azure.%s must be non-empty when auth_method is client_secret", f.name))
			}
		}
	case "workload_identity":
		for _, f := range []struct{ name, val string }{
			{"dcr_endpoint", c.Azure.DCREndpoint},
			{"dcr_immutable_id", c.Azure.DCRImmutableID},
		} {
			if f.val == "" {
				errs = append(errs, malformedf("azure.%s must be non-empty when auth_method is workload_identity", f.name))
			}
		}
	default:
		errs = append(errs, malformedf("azure.auth_method must be one of legacy, client_secret, workload_identity, got %q", c.Azure.AuthMethod))
	}
	// arc_autodiscovery is a typed bool; no string check needed.
	return errs
}

// FalconCloud maps the configured cloud_region string to the gofalcon
// CloudType. Validate() has already constrained cloud_region to the four
// supported regions; falcon.Cloud parses the same strings and falls back to
// us-1 for anything unrecognized.
func (c *Config) FalconCloud() falcon.CloudType {
	return falcon.Cloud(c.Falcon.CloudRegion)
}
