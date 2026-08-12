// Package config loads and validates FIG configuration.
//
// It is a port of fig/config/__init__.py. Configuration is layered with viper
// (lowest to highest precedence): code defaults -> optional config file ->
// environment variables -> [P3] credential store overlay. The config file may
// be INI, JSON, TOML, or YAML; the file extension selects the codec. The
// go-viper INI codec is registered so viper can parse the operator-facing
// config.ini, and JSON/TOML/YAML use viper's built-in codecs.
//
// This package is logging-independent: logging reads the resolved level from
// the returned Config, preserving the Python import-order constraint.
package config

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/go-viper/encoding/ini"
	"github.com/spf13/viper"
)

// Config is the fully-resolved, typed FIG configuration. Fields are populated
// by viper.Unmarshal via mapstructure tags matching the "section.key" layout;
// derived set/slice fields are computed in Load.
type Config struct {
	Main           MainConfig           `mapstructure:"main"`
	Events         EventsConfig         `mapstructure:"events"`
	Logging        LoggingConfig        `mapstructure:"logging"`
	Falcon         FalconConfig         `mapstructure:"falcon"`
	Credentials    CredentialsStore     `mapstructure:"credentials_store"`
	SSM            SSMConfig            `mapstructure:"ssm"`
	SecretsManager SecretsManagerConfig `mapstructure:"secrets_manager"`
	Generic        GenericConfig        `mapstructure:"generic"`
	AWS            AWSConfig            `mapstructure:"aws"`
	AWSSQS         AWSSQSConfig         `mapstructure:"aws_sqs"`
	Azure          AzureConfig          `mapstructure:"azure"`
	CloudTrailLake CloudTrailLakeConfig `mapstructure:"cloudtrail_lake"`
	WorkspaceOne   WorkspaceOneConfig   `mapstructure:"workspaceone"`
	Enrich         EnrichConfig         `mapstructure:"enrich"`

	// Derived fields (computed in Load, not unmarshalled directly).
	Backends                []string `mapstructure:"-"`
	DetectionsExcludeClouds []string `mapstructure:"-"`
}

// MainConfig is the [main] section.
type MainConfig struct {
	WorkerThreads int    `mapstructure:"worker_threads"`
	Backends      string `mapstructure:"backends"`
	// MetricsAddr is the listen address for the /metrics, /healthz, and /readyz
	// HTTP server (e.g. ":9090"). Empty disables the server, preserving the
	// Python daemon's no-HTTP-surface default.
	MetricsAddr string `mapstructure:"metrics_addr"`
	// QueueDepth is the bounded event-channel capacity (backpressure bound). A
	// value <= 0 selects the derived default of WorkerThreads*64, computed by
	// the app layer.
	QueueDepth int `mapstructure:"queue_depth"`
}

// EventsConfig is the [events] section.
type EventsConfig struct {
	SeverityThreshold       int    `mapstructure:"severity_threshold"`
	OlderThanDaysThreshold  int    `mapstructure:"older_than_days_threshold"`
	DetectionsExcludeClouds string `mapstructure:"detections_exclude_clouds"`
	Offset                  uint64 `mapstructure:"offset"`
	StartFromNewest         bool   `mapstructure:"start_from_newest"`
	OffsetStore             string `mapstructure:"offset_store"`
	OffsetStorePath         string `mapstructure:"offset_store_path"`
	DeliveryFailure         string `mapstructure:"delivery_failure"`
}

// LoggingConfig is the [logging] section.
type LoggingConfig struct {
	Level string `mapstructure:"level"`
}

// FalconConfig is the [falcon] section.
type FalconConfig struct {
	CloudRegion          string `mapstructure:"cloud"`
	ClientID             string `mapstructure:"client_id"`
	ClientSecret         string `mapstructure:"client_secret"`
	ApplicationID        string `mapstructure:"application_id"`
	ReconnectRetryCount  int    `mapstructure:"reconnect_retry_count"`
	RTRQuarantineKeyword string `mapstructure:"rtr_quarantine_keyword"`
}

// CredentialsStore is the [credentials_store] section.
type CredentialsStore struct {
	Store string `mapstructure:"store"`
}

// SSMConfig is the [ssm] section.
type SSMConfig struct {
	Region          string `mapstructure:"region"`
	SSMClientID     string `mapstructure:"ssm_client_id"`
	SSMClientSecret string `mapstructure:"ssm_client_secret"`
}

// SecretsManagerConfig is the [secrets_manager] section.
type SecretsManagerConfig struct {
	Region                        string `mapstructure:"region"`
	SecretsManagerSecretName      string `mapstructure:"secrets_manager_secret_name"`
	SecretsManagerClientIDKey     string `mapstructure:"secrets_manager_client_id_key"`
	SecretsManagerClientSecretKey string `mapstructure:"secrets_manager_client_secret_key"`
}

// GenericConfig is the [generic] section.
type GenericConfig struct {
	EventTypes string `mapstructure:"event_types"`
}

// AWSConfig is the [aws] section.
type AWSConfig struct {
	Region          string `mapstructure:"region"`
	ConfirmInstance bool   `mapstructure:"confirm_instance"`
	AcceptAllEvents bool   `mapstructure:"accept_all_events"`
}

// AWSSQSConfig is the [aws_sqs] section.
type AWSSQSConfig struct {
	Region       string `mapstructure:"region"`
	SQSQueueName string `mapstructure:"sqs_queue_name"`
}

// AzureConfig is the [azure] section.
type AzureConfig struct {
	WorkspaceID      string `mapstructure:"workspace_id"`
	PrimaryKey       string `mapstructure:"primary_key"`
	ArcAutodiscovery bool   `mapstructure:"arc_autodiscovery"`
	AuthMethod       string `mapstructure:"auth_method"`
	TenantID         string `mapstructure:"tenant_id"`
	ClientID         string `mapstructure:"client_id"`
	ClientSecret     string `mapstructure:"client_secret"`
	DCREndpoint      string `mapstructure:"dcr_endpoint"`
	DCRImmutableID   string `mapstructure:"dcr_immutable_id"`
}

// CloudTrailLakeConfig is the [cloudtrail_lake] section.
type CloudTrailLakeConfig struct {
	ChannelARN string `mapstructure:"channel_arn"`
	Region     string `mapstructure:"region"`
}

// WorkspaceOneConfig is the [workspaceone] section.
type WorkspaceOneConfig struct {
	Token      string `mapstructure:"token"`
	SyslogHost string `mapstructure:"syslog_host"`
	SyslogPort int    `mapstructure:"syslog_port"`
}

// EnrichConfig is the [enrich] section. It bounds the per-sensor caches that
// memoize host details and MDM identifiers so enrichment lookups stay off the
// hot path without growing without limit.
type EnrichConfig struct {
	CacheSize int    `mapstructure:"cache_size"`
	CacheTTL  string `mapstructure:"cache_ttl"`

	// CacheTTLDuration is CacheTTL parsed to a duration, computed in Load. The
	// INI codec surfaces the raw string; parsing here (rather than via a viper
	// decode hook) mirrors the derived-field pattern used for the CSV fields.
	CacheTTLDuration time.Duration `mapstructure:"-"`
}

// Load resolves configuration from defaults, an optional config file, and the
// environment. configPath is the --config flag value; it may point to an INI,
// JSON, TOML, or YAML file (the extension selects the codec) and viper rejects
// an unrecognized extension. When "" it searches /etc/fig, ./config, then . for
// a config.<ext> in any supported format. A missing config file is NOT an error
// (pure code defaults + env is a valid configuration).
//
// Load does NOT call Validate; callers should invoke cfg.Validate() explicitly.
func Load(configPath string) (*Config, error) {
	v, err := newViper()
	if err != nil {
		return nil, err
	}

	if configPath != "" {
		// The file extension selects the codec; viper rejects an unrecognized
		// extension with UnsupportedConfigError.
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			// An explicitly requested config file must exist.
			return nil, err
		}
	} else {
		// Search mode: viper matches config.<ext> across the supported
		// extensions and infers the codec from whichever it finds.
		v.SetConfigName("config")
		v.AddConfigPath("/etc/fig")
		v.AddConfigPath(".")
		if err := v.ReadInConfig(); err != nil {
			// Tolerate a missing config file: proceed on code defaults + env.
			var notFound viper.ConfigFileNotFoundError
			if !errors.As(err, &notFound) && !os.IsNotExist(err) {
				return nil, err
			}
		}
	}

	// [P3] Credential-store overlay hook: after the env layer, a credstore
	// loader will call v.Set("falcon.client_id", ...) / v.Set(
	// "falcon.client_secret", ...) here so those values take highest
	// precedence, matching fig/config/__init__.py:110-122.

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Derived fields: comma-split, trimmed. Empty string -> empty slice.
	cfg.Backends = splitCSV(cfg.Main.Backends)
	cfg.DetectionsExcludeClouds = splitCSV(cfg.Events.DetectionsExcludeClouds)

	// Derived duration: parse the raw cache_ttl string. A parse failure leaves
	// the duration zero; Validate is authoritative and reports the bad value.
	cfg.Enrich.CacheTTLDuration, _ = time.ParseDuration(cfg.Enrich.CacheTTL)

	return &cfg, nil
}

// envBinding maps a "section.key" viper path to an environment variable name.
// Port of ENV_DEFAULTS in fig/config/__init__.py:12-53. Names are preserved
// EXACTLY; the ordering (and the one-env->two-keys AWS_REGION case) matters.
type envBinding struct {
	Key string // "section.key"
	Env string
}

// envBindings ports ENV_DEFAULTS verbatim. Note AWS_REGION binds to BOTH
// aws.region and aws_sqs.region (one env var -> two keys).
var envBindings = []envBinding{
	{"main.backends", "FIG_BACKENDS"},
	{"main.worker_threads", "FIG_WORKER_THREADS"},
	{"main.metrics_addr", "FIG_METRICS_ADDR"},
	{"main.queue_depth", "FIG_QUEUE_DEPTH"},
	{"logging.level", "LOG_LEVEL"},
	{"events.severity_threshold", "EVENTS_SEVERITY_THRESHOLD"},
	{"events.older_than_days_threshold", "EVENTS_OLDER_THAN_DAYS_THRESHOLD"},
	{"events.offset", "EVENTS_OFFSET"},
	{"events.start_from_newest", "EVENTS_START_FROM_NEWEST"},
	{"falcon.cloud", "FALCON_CLOUD"},
	{"falcon.client_id", "FALCON_CLIENT_ID"},
	{"falcon.client_secret", "FALCON_CLIENT_SECRET"},
	{"falcon.reconnect_retry_count", "FALCON_RECONNECT_RETRY_COUNT"},
	{"falcon.application_id", "FALCON_APPLICATION_ID"},
	{"credentials_store.store", "CREDENTIALS_STORE"},
	{"ssm.region", "SSM_REGION"},
	{"ssm.ssm_client_id", "SSM_CLIENT_ID"},
	{"ssm.ssm_client_secret", "SSM_CLIENT_SECRET"},
	{"secrets_manager.region", "SECRETS_MANAGER_REGION"},
	{"secrets_manager.secrets_manager_secret_name", "SECRETS_MANAGER_SECRET_NAME"},
	{"secrets_manager.secrets_manager_client_id_key", "SECRETS_MANAGER_CLIENT_ID_KEY"},
	{"secrets_manager.secrets_manager_client_secret_key", "SECRETS_MANAGER_CLIENT_SECRET_KEY"},
	{"azure.workspace_id", "WORKSPACE_ID"},
	{"azure.primary_key", "PRIMARY_KEY"},
	{"azure.arc_autodiscovery", "ARC_AUTODISCOVERY"},
	{"azure.auth_method", "AZURE_AUTH_METHOD"},
	{"azure.tenant_id", "AZURE_TENANT_ID"},
	{"azure.client_id", "AZURE_CLIENT_ID"},
	{"azure.client_secret", "AZURE_CLIENT_SECRET"},
	{"azure.dcr_endpoint", "AZURE_DCR_ENDPOINT"},
	{"azure.dcr_immutable_id", "AZURE_DCR_IMMUTABLE_ID"},
	{"aws.region", "AWS_REGION"},
	{"aws.confirm_instance", "AWS_CONFIRM_INSTANCE"},
	{"aws.accept_all_events", "AWS_ACCEPT_ALL_EVENTS"},
	{"aws_sqs.region", "AWS_REGION"}, // one env var -> two keys
	{"aws_sqs.sqs_queue_name", "AWS_SQS"},
	{"workspaceone.token", "WORKSPACEONE_TOKEN"},
	{"workspaceone.syslog_host", "SYSLOG_HOST"},
	{"workspaceone.syslog_port", "SYSLOG_PORT"},
	{"cloudtrail_lake.channel_arn", "CLOUDTRAIL_LAKE_CHANNEL_ARN"},
	{"cloudtrail_lake.region", "CLOUDTRAIL_LAKE_REGION"},
	{"generic.event_types", "GENERIC_EVENT_TYPES"},
	{"enrich.cache_size", "ENRICH_CACHE_SIZE"},
	{"enrich.cache_ttl", "ENRICH_CACHE_TTL"},
}

// setDefaults registers every default value. Port of config/defaults.ini —
// defaults now live in code (viper's lowest precedence), replacing the shipped
// defaults.ini per the approved plan.
func setDefaults(v *viper.Viper) {
	v.SetDefault("main.worker_threads", 4)
	v.SetDefault("main.backends", "GENERIC")
	v.SetDefault("main.metrics_addr", "")
	v.SetDefault("main.queue_depth", 0)

	v.SetDefault("events.severity_threshold", 2)
	v.SetDefault("events.older_than_days_threshold", 21)
	v.SetDefault("events.detections_exclude_clouds", "")
	v.SetDefault("events.offset", 0)
	v.SetDefault("events.start_from_newest", false)
	v.SetDefault("events.offset_store", "file")
	v.SetDefault("events.offset_store_path", "offsets.json")
	v.SetDefault("events.delivery_failure", "dlq")

	v.SetDefault("logging.level", "INFO")

	v.SetDefault("falcon.cloud", "autodiscover")
	v.SetDefault("falcon.client_id", "")
	v.SetDefault("falcon.client_secret", "")
	v.SetDefault("falcon.application_id", "fig-default-app-id")
	v.SetDefault("falcon.reconnect_retry_count", 36)
	v.SetDefault("falcon.rtr_quarantine_keyword", "infected")

	v.SetDefault("credentials_store.store", "")

	v.SetDefault("generic.event_types", "ALL")

	v.SetDefault("aws.confirm_instance", true)
	v.SetDefault("aws.accept_all_events", false)
	v.SetDefault("aws.region", "")

	v.SetDefault("aws_sqs.region", "")
	v.SetDefault("aws_sqs.sqs_queue_name", "")

	v.SetDefault("azure.arc_autodiscovery", false)
	v.SetDefault("azure.auth_method", "legacy")
	v.SetDefault("azure.workspace_id", "")
	v.SetDefault("azure.primary_key", "")
	v.SetDefault("azure.tenant_id", "")
	v.SetDefault("azure.client_id", "")
	v.SetDefault("azure.client_secret", "")
	v.SetDefault("azure.dcr_endpoint", "")
	v.SetDefault("azure.dcr_immutable_id", "")

	v.SetDefault("cloudtrail_lake.channel_arn", "")
	v.SetDefault("cloudtrail_lake.region", "")

	v.SetDefault("workspaceone.token", "")
	v.SetDefault("workspaceone.syslog_host", "")
	v.SetDefault("workspaceone.syslog_port", 6514)

	v.SetDefault("ssm.region", "")
	v.SetDefault("ssm.ssm_client_id", "")
	v.SetDefault("ssm.ssm_client_secret", "")

	v.SetDefault("secrets_manager.region", "")
	v.SetDefault("secrets_manager.secrets_manager_secret_name", "")
	v.SetDefault("secrets_manager.secrets_manager_client_id_key", "")
	v.SetDefault("secrets_manager.secrets_manager_client_secret_key", "")

	v.SetDefault("enrich.cache_size", 8192)
	v.SetDefault("enrich.cache_ttl", "1h")
}

// bindEnv registers explicit per-key env bindings. Explicit binds (not
// AutomaticEnv) preserve the exact env var names and the one-env->two-keys case.
func bindEnv(v *viper.Viper) error {
	for _, b := range envBindings {
		if err := v.BindEnv(b.Key, b.Env); err != nil {
			return err
		}
	}
	return nil
}

// newViper builds a viper instance with the INI codec registered for the "ini"
// format, defaults set, and env bindings applied.
func newViper() (*viper.Viper, error) {
	registry := viper.NewCodecRegistry()
	if err := registry.RegisterCodec("ini", ini.Codec{}); err != nil {
		return nil, err
	}
	v := viper.NewWithOptions(viper.WithCodecRegistry(registry))
	setDefaults(v)
	if err := bindEnv(v); err != nil {
		return nil, err
	}
	return v, nil
}

// splitCSV splits a comma-separated string into trimmed, non-empty tokens.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
