// Package config loads and validates FIG configuration.
//
// It is a port of fig/config/__init__.py. Configuration is layered with viper
// (lowest to highest precedence): code defaults -> optional config file ->
// environment variables. The config file may
// be INI, JSON, TOML, or YAML; the file extension selects the codec. The
// go-viper INI codec is registered so viper can parse the operator-facing
// config.ini, and JSON/TOML/YAML use viper's built-in codecs.
//
// This package is logging-independent: logging reads the resolved level from
// the returned Config rather than the other way around.
package config

import (
	"errors"
	"os"
	"time"

	"github.com/go-viper/encoding/ini"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/crowdstrike/falcon-integration-gateway/internal/utils"
)

// Config is the fully-resolved, typed FIG configuration. Fields are populated
// by viper.Unmarshal via mapstructure tags matching the "section.key" layout;
// derived set/slice fields are computed in Load.
type Config struct {
	Gateway        GatewayConfig        `mapstructure:"gateway"`
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
	Cache          CacheConfig          `mapstructure:"cache"`

	// Derived fields (computed in Load, not unmarshalled directly).
	Backends                []string `mapstructure:"-"`
	DetectionsExcludeClouds []string `mapstructure:"-"`
}

// GatewayConfig is the [gateway] section.
type GatewayConfig struct {
	WorkerThreads int    `mapstructure:"worker_threads"`
	Backends      string `mapstructure:"backends"`
	// MetricsAddr is the listen address for the /metrics, /healthz, and /readyz
	// HTTP server (e.g. ":9090"). Empty disables the server, so no HTTP
	// surface is exposed by default.
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
	OffsetStoreRegion       string `mapstructure:"offset_store_region"`
	DeliveryFailure         string `mapstructure:"delivery_failure"`
	// PendingWarnThreshold is the number of completed-but-not-yet-committed
	// offsets on a single feed above which the pipeline logs a throttled warning
	// that its resume watermark is not advancing (a likely offset gap). Zero
	// disables the warning.
	PendingWarnThreshold int `mapstructure:"pending_warn_threshold"`
	// PendingMax caps the number of completed-but-not-yet-committed offsets a
	// single feed may hold before the pipeline stops accepting more under the
	// block policy (surfaced via fig_pending_overflow_total). Zero disables the
	// cap (unbounded, the historical behavior).
	PendingMax int `mapstructure:"pending_max"`
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
	TLSVerify  bool   `mapstructure:"tls_verify"`
}

// CacheConfig is the [cache] section. It bounds the per-sensor caches that
// memoize host details and MDM identifiers so enrichment lookups stay off the
// hot path without growing without limit.
type CacheConfig struct {
	Size int    `mapstructure:"size"`
	TTL  string `mapstructure:"ttl"`

	// TTLDuration is TTL parsed to a duration, computed in Load. The INI codec
	// surfaces the raw string; parsing here (rather than via a viper decode
	// hook) mirrors the derived-field pattern used for the CSV fields.
	TTLDuration time.Duration `mapstructure:"-"`
}

// Load resolves configuration from defaults, an optional config file, the
// environment, and CLI flags. configPath is the --config flag value; it may
// point to an INI, JSON, TOML, or YAML file (the extension selects the codec)
// and viper rejects an unrecognized extension. When "" it searches /etc/fig,
// ./config, then . for a config.<ext> in any supported format. A missing config
// file is NOT an error (pure code defaults + env is a valid configuration).
//
// flags is the cobra command's flag set (from RegisterFlags); when non-nil its
// flags are bound so a flag set on the command line takes highest precedence
// (flag > env > file > default). Pass nil when no flags are involved.
//
// Load does NOT call Validate; callers should invoke cfg.Validate() explicitly.
func Load(configPath string, flags *pflag.FlagSet) (*Config, error) {
	v, err := newViper()
	if err != nil {
		return nil, err
	}

	if flags != nil {
		if err := bindFlags(v, flags); err != nil {
			return nil, err
		}
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

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Derived fields: comma-split, trimmed. Empty string -> empty slice.
	cfg.Backends = utils.SplitCSV(cfg.Gateway.Backends)
	cfg.DetectionsExcludeClouds = utils.SplitCSV(cfg.Events.DetectionsExcludeClouds)

	// Derived duration: parse the raw cache ttl string. A parse failure leaves
	// the duration zero; Validate is authoritative and reports the bad value.
	cfg.Cache.TTLDuration, _ = time.ParseDuration(cfg.Cache.TTL)

	return &cfg, nil
}

// setting is one row of the configuration catalog: a viper "section.key" and
// its default, plus the optional environment variable and CLI flag that feed
// it. It is a port of ENV_DEFAULTS/config/defaults.ini in fig/config/__init__.py,
// consolidated so defaults, env bindings, and flags stay in lockstep. Default
// holds a typed value (string, int, uint64, or bool); its type selects the
// pflag registered for Flag and must match the field's mapstructure type.
type setting struct {
	Key     string // "section.key"
	Flag    string // CLI long flag name; "" = no flag
	Env     string // environment variable; "" = no env binding
	Default any    // typed default value
	Usage   string // --help text
	Group   string // --help heading; must be one of groupOrder
}

// Flag-group headings for --help. groupOrder fixes their display order; every
// setting that defines a Flag must name one of these in its Group field.
const (
	groupGateway        = "Gateway & Runtime"
	groupEvents         = "Event Filtering & Offsets"
	groupFalcon         = "Falcon API"
	groupExternalStores = "Credential Stores"
	groupBackends       = "Backends"
	groupCache          = "Enrichment"
)

var groupOrder = []string{groupGateway, groupEvents, groupFalcon, groupExternalStores, groupBackends, groupCache}

// settings is the single source of truth for FIG configuration. Note that
// AWS_REGION binds to BOTH aws.region and aws_sqs.region (one env var -> two
// keys), expressed here as two rows. --config is not listed: it selects the
// config file rather than a key.
// The Group column places each flag under a --help heading (see groupOrder).
var settings = []setting{
	// [gateway]
	{"gateway.worker_threads", "worker-threads", "FIG_WORKER_THREADS", 4, "number of worker threads", groupGateway},
	{"gateway.backends", "backends", "FIG_BACKENDS", "GENERIC", "comma-separated list of backends to enable", groupGateway},
	{"gateway.metrics_addr", "metrics-addr", "FIG_METRICS_ADDR", "", "listen address for the /metrics, /healthz, /readyz HTTP server", groupGateway},
	{"gateway.queue_depth", "queue-depth", "FIG_QUEUE_DEPTH", 0, "bounded event-channel capacity", groupGateway},

	// [events]
	{"events.severity_threshold", "severity-threshold", "EVENTS_SEVERITY_THRESHOLD", 2, "minimum event severity to forward", groupEvents},
	{"events.older_than_days_threshold", "older-than-days-threshold", "EVENTS_OLDER_THAN_DAYS_THRESHOLD", 21, "drop events older than this many days", groupEvents},
	{"events.detections_exclude_clouds", "detections-exclude-clouds", "", "", "comma-separated clouds to exclude from detection events", groupEvents},
	{"events.offset", "offset", "EVENTS_OFFSET", uint64(0), "stream offset to resume from (mutually exclusive with start_from_newest)", groupEvents},
	{"events.start_from_newest", "start-from-newest", "EVENTS_START_FROM_NEWEST", false, "start from the newest event on the initial connection", groupEvents},
	{"events.offset_store", "offset-store", "", "file", "offset store backend", groupEvents},
	{"events.offset_store_path", "offset-store-path", "", "offsets.json", "path to the file offset store, or the SSM parameter name when offset_store=ssm", groupEvents},
	{"events.offset_store_region", "offset-store-region", "", "", "AWS region for the ssm offset store", groupEvents},
	{"events.delivery_failure", "delivery-failure", "", "drop", "delivery-failure handling mode (drop|discard|block; dlq is a deprecated alias for drop)", groupEvents},
	{"events.pending_warn_threshold", "pending-warn-threshold", "", 1000, "warn when a feed holds more than this many uncommitted offsets (0 disables)", groupEvents},
	{"events.pending_max", "pending-max", "", 0, "cap on uncommitted offsets per feed under the block policy (0 disables)", groupEvents},

	// [logging]
	{"logging.level", "log-level", "LOG_LEVEL", "INFO", "log level", groupGateway},

	// [falcon]
	{"falcon.cloud", "falcon-cloud", "FALCON_CLOUD", "autodiscover", "Falcon cloud region", groupFalcon},
	{"falcon.client_id", "falcon-client-id", "FALCON_CLIENT_ID", "", "Falcon API client ID", groupFalcon},
	{"falcon.client_secret", "falcon-client-secret", "FALCON_CLIENT_SECRET", "", "Falcon API client secret", groupFalcon},
	{"falcon.application_id", "falcon-application-id", "FALCON_APPLICATION_ID", "fig-default-app-id", "Falcon stream application ID", groupFalcon},
	{"falcon.reconnect_retry_count", "falcon-reconnect-retry-count", "FALCON_RECONNECT_RETRY_COUNT", 36, "stream reconnect retry count", groupFalcon},
	{"falcon.rtr_quarantine_keyword", "falcon-rtr-quarantine-keyword", "", "infected", "RTR quarantine keyword", groupFalcon},

	// [credentials_store]
	{"credentials_store.store", "credentials-store", "CREDENTIALS_STORE", "", "credential store backend", groupExternalStores},

	// [ssm]
	{"ssm.region", "aws-ssm-region", "SSM_REGION", "", "AWS SSM region", groupExternalStores},
	{"ssm.ssm_client_id", "aws-ssm-client-id", "SSM_CLIENT_ID", "", "AWS SSM parameter name for the Falcon client ID", groupExternalStores},
	{"ssm.ssm_client_secret", "aws-ssm-client-secret", "SSM_CLIENT_SECRET", "", "AWS SSM parameter name for the Falcon client secret", groupExternalStores},

	// [secrets_manager]
	{"secrets_manager.region", "secrets-manager-region", "SECRETS_MANAGER_REGION", "", "AWS Secrets Manager region", groupExternalStores},
	{"secrets_manager.secrets_manager_secret_name", "secrets-manager-secret-name", "SECRETS_MANAGER_SECRET_NAME", "", "AWS Secrets Manager secret name", groupExternalStores},
	{"secrets_manager.secrets_manager_client_id_key", "secrets-manager-client-id-key", "SECRETS_MANAGER_CLIENT_ID_KEY", "", "AWS Secrets Manager key for the Falcon client ID", groupExternalStores},
	{"secrets_manager.secrets_manager_client_secret_key", "secrets-manager-client-secret-key", "SECRETS_MANAGER_CLIENT_SECRET_KEY", "", "AWS Secrets Manager key for the Falcon client secret", groupExternalStores},

	// [generic]
	{"generic.event_types", "generic-event-types", "GENERIC_EVENT_TYPES", "ALL", "comma-separated event types for the GENERIC backend, or ALL", groupBackends},

	// [aws]
	{"aws.region", "aws-region", "AWS_REGION", "", "AWS region for Security Hub", groupBackends},
	{"aws.confirm_instance", "aws-confirm-instance", "AWS_CONFIRM_INSTANCE", true, "confirm the EC2 instance before submitting findings", groupBackends},
	{"aws.accept_all_events", "aws-accept-all-events", "AWS_ACCEPT_ALL_EVENTS", false, "submit findings for all events, not just AWS instances", groupBackends},

	// [aws_sqs]
	{"aws_sqs.region", "aws-sqs-region", "AWS_REGION", "", "AWS region for the SQS queue", groupBackends}, // AWS_REGION -> two keys
	{"aws_sqs.sqs_queue_name", "aws-sqs-queue-name", "AWS_SQS", "", "AWS SQS queue name", groupBackends},

	// [azure]
	{"azure.workspace_id", "azure-workspace-id", "WORKSPACE_ID", "", "Azure Log Analytics workspace ID (legacy auth)", groupBackends},
	{"azure.primary_key", "azure-primary-key", "PRIMARY_KEY", "", "Azure Log Analytics primary key (legacy auth)", groupBackends},
	{"azure.arc_autodiscovery", "azure-arc-autodiscovery", "ARC_AUTODISCOVERY", false, "enable Azure Arc autodiscovery", groupBackends},
	{"azure.auth_method", "azure-auth-method", "AZURE_AUTH_METHOD", "legacy", "Azure auth method", groupBackends},
	{"azure.tenant_id", "azure-tenant-id", "AZURE_TENANT_ID", "", "Azure tenant ID", groupBackends},
	{"azure.client_id", "azure-client-id", "AZURE_CLIENT_ID", "", "Azure client ID", groupBackends},
	{"azure.client_secret", "azure-client-secret", "AZURE_CLIENT_SECRET", "", "Azure client secret", groupBackends},
	{"azure.dcr_endpoint", "azure-dcr-endpoint", "AZURE_DCR_ENDPOINT", "", "Azure Data Collection Rule endpoint", groupBackends},
	{"azure.dcr_immutable_id", "azure-dcr-immutable-id", "AZURE_DCR_IMMUTABLE_ID", "", "Azure Data Collection Rule immutable ID", groupBackends},

	// [cloudtrail_lake]
	{"cloudtrail_lake.channel_arn", "cloudtrail-lake-channel-arn", "CLOUDTRAIL_LAKE_CHANNEL_ARN", "", "AWS CloudTrail Lake channel ARN", groupBackends},
	{"cloudtrail_lake.region", "cloudtrail-lake-region", "CLOUDTRAIL_LAKE_REGION", "", "AWS CloudTrail Lake region", groupBackends},

	// [workspaceone]
	{"workspaceone.token", "workspaceone-token", "WORKSPACEONE_TOKEN", "", "Workspace ONE syslog token", groupBackends},
	{"workspaceone.syslog_host", "workspaceone-syslog-host", "SYSLOG_HOST", "", "Workspace ONE syslog host", groupBackends},
	{"workspaceone.syslog_port", "workspaceone-syslog-port", "SYSLOG_PORT", 6514, "Workspace ONE syslog port", groupBackends},
	{"workspaceone.tls_verify", "workspaceone-tls-verify", "WORKSPACEONE_TLS_VERIFY", false, "verify the Workspace ONE syslog server's TLS certificate (default false for parity)", groupBackends},

	// [cache]
	{"cache.size", "cache-size", "CACHE_SIZE", 8192, "enrichment cache size", groupCache},
	{"cache.ttl", "cache-ttl", "CACHE_TTL", "1h", "enrichment cache TTL", groupCache},
}

// setDefaults registers every default value as viper's lowest-precedence layer.
func setDefaults(v *viper.Viper) {
	for _, s := range settings {
		v.SetDefault(s.Key, s.Default)
	}
}

// envAliases lists additional, lower-precedence environment variable names for a
// key beyond its primary settings.Env. The Falcon cloud region is also set by the
// shipped k8s and helm manifests as FALCON_CLOUD_REGION, so it is accepted
// alongside the primary FALCON_CLOUD name.
var envAliases = map[string][]string{
	"falcon.cloud": {"FALCON_CLOUD_REGION"},
}

// bindEnv registers explicit per-key env bindings. Explicit binds (not
// AutomaticEnv) preserve the exact env var names and the one-env->two-keys case.
// When a key has aliases, all names are bound in a single BindEnv call because a
// second call for the same key would replace the first; viper resolves them
// first-match-wins, so the primary Env name takes precedence over any alias.
func bindEnv(v *viper.Viper) error {
	for _, s := range settings {
		if s.Env == "" {
			continue
		}
		names := append([]string{s.Env}, envAliases[s.Key]...)
		if err := v.BindEnv(append([]string{s.Key}, names...)...); err != nil {
			return err
		}
	}
	return nil
}

// NamedFlagSet pairs a --help heading with the flags shown under it. The order
// of the slice returned by RegisterFlags is the display order (see groupOrder).
type NamedFlagSet struct {
	Name    string
	FlagSet *pflag.FlagSet
}

// registerFlag declares a single pflag on fs using the setting's typed default,
// so --help reports the real default and viper's BindPFlag can resolve
// precedence. Settings with no Flag are skipped by the caller.
func registerFlag(fs *pflag.FlagSet, s setting) {
	switch d := s.Default.(type) {
	case string:
		fs.String(s.Flag, d, s.Usage)
	case int:
		fs.Int(s.Flag, d, s.Usage)
	case uint64:
		fs.Uint64(s.Flag, d, s.Usage)
	case bool:
		fs.Bool(s.Flag, d, s.Usage)
	}
}

// RegisterFlags declares a CLI flag for every setting that defines one and adds
// it to fs, so viper's BindPFlag resolves precedence to flag > env > file >
// default. Flags are also collected into per-group flag sets (in groupOrder,
// preserving catalog order within each group) and returned so the caller can
// render grouped --help output. Any flag whose Group is not in groupOrder lands
// in a trailing catch-all group so it is never silently dropped; a unit test
// guards against that happening.
func RegisterFlags(fs *pflag.FlagSet) []NamedFlagSet {
	const catchAll = "Other Flags"

	byName := make(map[string]*pflag.FlagSet, len(groupOrder)+1)
	order := append([]string(nil), groupOrder...)
	group := func(name string) *pflag.FlagSet {
		set, ok := byName[name]
		if !ok {
			set = pflag.NewFlagSet(name, pflag.ContinueOnError)
			set.SortFlags = false
			byName[name] = set
			if name == catchAll {
				order = append(order, catchAll)
			}
		}
		return set
	}
	for _, name := range groupOrder {
		group(name)
	}

	for _, s := range settings {
		if s.Flag == "" {
			continue
		}
		name := s.Group
		if _, known := byName[name]; !known || name == "" {
			name = catchAll
		}
		registerFlag(group(name), s)
	}

	groups := make([]NamedFlagSet, 0, len(order))
	for _, name := range order {
		set := byName[name]
		fs.AddFlagSet(set)
		groups = append(groups, NamedFlagSet{Name: name, FlagSet: set})
	}
	return groups
}

// bindFlags binds each setting's registered flag to its viper key so a flag set
// on the command line overrides env, file, and default values.
func bindFlags(v *viper.Viper, fs *pflag.FlagSet) error {
	for _, s := range settings {
		if s.Flag == "" {
			continue
		}
		flag := fs.Lookup(s.Flag)
		if flag == nil {
			continue
		}
		if err := v.BindPFlag(s.Key, flag); err != nil {
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
