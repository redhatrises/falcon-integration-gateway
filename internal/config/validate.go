package config

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
)

// Valid enumerations. Port of the sets in fig/config/__init__.py:9-11.
var (
	// validBackendNames lists the recognized backend names. It is duplicated
	// here (rather than importing the backend registry) to avoid an import
	// cycle; keep it in sync with backend.Names().
	validBackendNames = []string{"AWS", "AWS_SQS", "AZURE", "GCP", "WORKSPACEONE", "CLOUDTRAIL_LAKE", "GENERIC"}

	validCloudRegions = []string{"autodiscover", "us-1", "us-2", "us-3", "eu-1", "us-gov-1", "us-gov-2"}

	sensorRecognizedClouds = []string{"AWS", "Azure", "GCP", "unrecognized"}
)

// ValidBackendNames returns a copy of the recognized backend names. It exists so
// a test can assert this list stays in sync with the backend registry
// (backend.Names), which config cannot import directly without an import cycle.
func ValidBackendNames() []string {
	return append([]string(nil), validBackendNames...)
}

// malformedf builds a validation error carrying the standard
// "malformed configuration: " prefix, so every site states only its specific
// problem.
func malformedf(format string, args ...any) error {
	return fmt.Errorf("malformed configuration: "+format, args...)
}

// field is a named value checked by appendIfEmpty.
type field struct{ name, val string }

// appendIfEmpty appends msg(f.name) for each field whose value is blank,
// returning the extended slice. It unifies the per-backend and per-auth-method
// "must be non-empty" checks; the only per-site difference is the message text,
// supplied by msg.
func appendIfEmpty(errs []error, msg func(name string) error, fields ...field) []error {
	for _, f := range fields {
		if f.val == "" {
			errs = append(errs, msg(f.name))
		}
	}
	return errs
}

// Validate ports every branch of validate()/validate_falcon()/validate_events()/
// validate_backends() (fig/config/__init__.py:142-238). Unlike the Python code
// (which fails on the first error), it accumulates ALL problems with
// errors.Join so the operator sees every misconfiguration at once.
func (c *Config) Validate() error {
	var errs []error

	// main
	if c.Gateway.WorkerThreads < 1 || c.Gateway.WorkerThreads > 127 {
		errs = append(errs, malformedf("expected worker_threads to be in range 1-127"))
	}

	errs = append(errs, c.validateFalcon()...)
	errs = append(errs, c.validateEvents()...)
	errs = append(errs, c.validateBackends()...)
	errs = append(errs, c.validateCache()...)

	return errors.Join(errs...)
}

// validateFalcon ports validate_falcon().
func (c *Config) validateFalcon() []error {
	var errs []error
	if c.Falcon.ReconnectRetryCount < 1 || c.Falcon.ReconnectRetryCount > 9999 {
		errs = append(errs, malformedf("expected reconnect_retry_count to be in range 1-9999"))
	}
	if !slices.Contains(validCloudRegions, c.Falcon.CloudRegion) {
		errs = append(errs, malformedf("expected cloud to be one of %s, got %q", strings.Join(validCloudRegions, ", "), c.Falcon.CloudRegion))
	}
	return errs
}

// validateEvents ports validate_events(). Note: start_from_newest is a real
// bool here, so the Python "must be true or false" string check is unnecessary.
func (c *Config) validateEvents() []error {
	var errs []error

	for _, cloud := range c.DetectionsExcludeClouds {
		if !slices.Contains(sensorRecognizedClouds, cloud) {
			errs = append(errs, malformedf("expected detections_exclude_clouds to be a subset of {%s}, got %q", strings.Join(sensorRecognizedClouds, ", "), cloud))
		}
	}

	if c.Events.SeverityThreshold < 1 || c.Events.SeverityThreshold > 5 {
		errs = append(errs, malformedf("expected severity_threshold to be in range 1-5"))
	}
	if c.Events.OlderThanDaysThreshold < 0 || c.Events.OlderThanDaysThreshold > 9999 {
		errs = append(errs, malformedf("expected older_than_days_threshold to be in range 0-9999"))
	}

	// start_from_newest XOR offset != 0.
	if c.Events.StartFromNewest && c.Events.Offset != 0 {
		errs = append(errs, malformedf("start_from_newest and offset are mutually exclusive. When start_from_newest is true, offset must be 0 (default)"))
	}

	switch strings.ToLower(strings.TrimSpace(c.Events.DeliveryFailure)) {
	case "", "drop", "discard", "dlq", "block":
	default:
		errs = append(errs, malformedf("expected delivery_failure to be one of {drop, discard, block} (dlq is a deprecated alias for drop), got %q", c.Events.DeliveryFailure))
	}
	if c.Events.PendingWarnThreshold < 0 {
		errs = append(errs, malformedf("expected pending_warn_threshold to be >= 0 (0 disables), got %d", c.Events.PendingWarnThreshold))
	}
	if c.Events.PendingMax < 0 {
		errs = append(errs, malformedf("expected pending_max to be >= 0 (0 disables), got %d", c.Events.PendingMax))
	}

	return errs
}

// validateBackends ports validate_backends().
func (c *Config) validateBackends() []error {
	var errs []error

	if len(c.Backends) < 1 {
		errs = append(errs, malformedf("expected backends to contain at least one backend"))
	}
	for _, b := range c.Backends {
		if !slices.Contains(validBackendNames, b) {
			errs = append(errs, malformedf("unrecognized backend %q; expected a subset of {%s}", b, strings.Join(validBackendNames, ", ")))
		}
	}

	// nonEmpty is the message builder for the per-backend "must be non-empty"
	// checks in validate_backends().
	nonEmpty := func(name string) error { return malformedf("expected %s to be non-empty", name) }

	if slices.Contains(c.Backends, "AWS") {
		errs = appendIfEmpty(errs, nonEmpty, field{"AWS region", c.AWS.Region})
		// confirm_instance / accept_all_events are typed bools; no string check needed.
	}
	if slices.Contains(c.Backends, "AWS_SQS") {
		errs = appendIfEmpty(errs, nonEmpty,
			field{"AWS_SQS region", c.AWSSQS.Region},
			field{"AWS_SQS sqs_queue_name", c.AWSSQS.SQSQueueName})
	}
	if slices.Contains(c.Backends, "WORKSPACEONE") {
		errs = appendIfEmpty(errs, nonEmpty,
			field{"token", c.WorkspaceOne.Token},
			field{"syslog_host", c.WorkspaceOne.SyslogHost})
		if c.WorkspaceOne.SyslogPort < 1 || c.WorkspaceOne.SyslogPort > 65534 {
			errs = append(errs, malformedf("expected syslog_port to be in range 1-65534"))
		}
	}
	if slices.Contains(c.Backends, "CLOUDTRAIL_LAKE") {
		errs = appendIfEmpty(errs, nonEmpty,
			field{"CLOUDTRAIL_LAKE channel_arn", c.CloudTrailLake.ChannelARN},
			field{"CLOUDTRAIL_LAKE region", c.CloudTrailLake.Region})
	}
	if slices.Contains(c.Backends, "AZURE") {
		errs = append(errs, c.validateAzure()...)
	}

	return errs
}

// validateCache bounds the enrichment caches: size must be a sane positive
// capacity and ttl must parse to a non-negative duration.
func (c *Config) validateCache() []error {
	var errs []error
	if c.Cache.Size < 1 || c.Cache.Size > 1_000_000 {
		errs = append(errs, malformedf("expected size to be in range 1-1000000"))
	}
	d, err := time.ParseDuration(c.Cache.TTL)
	switch {
	case err != nil:
		errs = append(errs, malformedf("expected ttl to be a valid duration (e.g. 1h, 30m), got %q", c.Cache.TTL))
	case d < 0:
		errs = append(errs, malformedf("expected ttl to be non-negative, got %q", c.Cache.TTL))
	}
	return errs
}

// validateAzure ports the AZURE branch, covering the three auth methods.
func (c *Config) validateAzure() []error {
	var errs []error
	switch c.Azure.AuthMethod {
	case "legacy":
		errs = appendIfEmpty(errs,
			func(name string) error { return malformedf("expected %s to be non-empty", name) },
			field{"workspace_id", c.Azure.WorkspaceID},
			field{"primary_key", c.Azure.PrimaryKey})
	case "client_secret":
		errs = appendIfEmpty(errs,
			func(name string) error {
				return malformedf("%s must be non-empty when auth_method is client_secret", name)
			},
			field{"tenant_id", c.Azure.TenantID},
			field{"client_id", c.Azure.ClientID},
			field{"client_secret", c.Azure.ClientSecret},
			field{"dcr_endpoint", c.Azure.DCREndpoint},
			field{"dcr_immutable_id", c.Azure.DCRImmutableID})
	case "workload_identity":
		errs = appendIfEmpty(errs,
			func(name string) error {
				return malformedf("azure.%s must be non-empty when auth_method is workload_identity", name)
			},
			field{"dcr_endpoint", c.Azure.DCREndpoint},
			field{"dcr_immutable_id", c.Azure.DCRImmutableID})
	default:
		errs = append(errs, malformedf("auth_method must be one of legacy, client_secret, workload_identity, got %q", c.Azure.AuthMethod))
	}
	// arc_autodiscovery is a typed bool; no string check needed.
	return errs
}

// FalconCloud maps the configured cloud region string to the gofalcon
// CloudType. Validate() has already constrained cloud to one of the supported
// regions; falcon.Cloud parses the same strings and falls back to us-1 for
// anything unrecognized.
func (c *Config) FalconCloud() falcon.CloudType {
	return falcon.Cloud(c.Falcon.CloudRegion)
}
