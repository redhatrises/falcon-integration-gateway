package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// loadFresh loads config with the given path, ensuring no stray config.ini in
// CWD interferes by running from a temp dir when path is empty.
func TestDefaultsApplyWithNoFileOrEnv(t *testing.T) {
	// Run in a temp dir so no config.ini is discovered on the search path.
	dir := t.TempDir()
	chdir(t, dir)

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Gateway.WorkerThreads != 4 {
		t.Errorf("worker_threads = %d, want 4", cfg.Gateway.WorkerThreads)
	}
	if cfg.Events.SeverityThreshold != 2 {
		t.Errorf("severity_threshold = %d, want 2", cfg.Events.SeverityThreshold)
	}
	if cfg.Events.OlderThanDaysThreshold != 21 {
		t.Errorf("older_than_days_threshold = %d, want 21", cfg.Events.OlderThanDaysThreshold)
	}
	if cfg.Logging.Level != "INFO" {
		t.Errorf("logging.level = %q, want INFO", cfg.Logging.Level)
	}
	if cfg.Falcon.CloudRegion != "autodiscover" {
		t.Errorf("cloud_region = %q, want autodiscover", cfg.Falcon.CloudRegion)
	}
	if cfg.Falcon.ApplicationID != "fig-default-app-id" {
		t.Errorf("application_id = %q", cfg.Falcon.ApplicationID)
	}
	if cfg.Falcon.ReconnectRetryCount != 36 {
		t.Errorf("reconnect_retry_count = %d, want 36", cfg.Falcon.ReconnectRetryCount)
	}
	if cfg.Generic.EventTypes != "ALL" {
		t.Errorf("generic.event_types = %q, want ALL", cfg.Generic.EventTypes)
	}
	if !cfg.AWS.ConfirmInstance {
		t.Errorf("aws.confirm_instance = false, want true")
	}
	if cfg.WorkspaceOne.SyslogPort != 6514 {
		t.Errorf("workspaceone.syslog_port = %d, want 6514", cfg.WorkspaceOne.SyslogPort)
	}
	if cfg.Events.OffsetStore != "file" {
		t.Errorf("events.offset_store = %q, want file", cfg.Events.OffsetStore)
	}
	if len(cfg.Backends) != 1 || cfg.Backends[0] != "GENERIC" {
		t.Errorf("Backends = %v, want [GENERIC]", cfg.Backends)
	}
	if len(cfg.DetectionsExcludeClouds) != 0 {
		t.Errorf("DetectionsExcludeClouds = %v, want empty", cfg.DetectionsExcludeClouds)
	}
}

func TestEnvBeatsDefault(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	t.Setenv("FIG_WORKER_THREADS", "9")
	t.Setenv("LOG_LEVEL", "DEBUG")

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Gateway.WorkerThreads != 9 {
		t.Errorf("worker_threads = %d, want 9 (env override)", cfg.Gateway.WorkerThreads)
	}
	if cfg.Logging.Level != "DEBUG" {
		t.Errorf("logging.level = %q, want DEBUG (env override)", cfg.Logging.Level)
	}
}

func TestConfigFileBeatsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	contents := "[gateway]\nworker_threads = 7\n\n[logging]\nlevel = WARN\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Gateway.WorkerThreads != 7 {
		t.Errorf("worker_threads = %d, want 7 (file override)", cfg.Gateway.WorkerThreads)
	}
	if cfg.Logging.Level != "WARN" {
		t.Errorf("logging.level = %q, want WARN (file override)", cfg.Logging.Level)
	}
}

func TestEnvBeatsConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	if err := os.WriteFile(path, []byte("[gateway]\nworker_threads = 7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FIG_WORKER_THREADS", "11")

	cfg, err := Load(path, nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Gateway.WorkerThreads != 11 {
		t.Errorf("worker_threads = %d, want 11 (env beats file)", cfg.Gateway.WorkerThreads)
	}
}

func TestAWSRegionDualBind(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	t.Setenv("AWS_REGION", "eu-central-1")
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.AWS.Region != "eu-central-1" {
		t.Errorf("aws.region = %q, want eu-central-1", cfg.AWS.Region)
	}
	if cfg.AWSSQS.Region != "eu-central-1" {
		t.Errorf("aws_sqs.region = %q, want eu-central-1 (dual bind)", cfg.AWSSQS.Region)
	}
}

func TestMissingExplicitConfigFileErrors(t *testing.T) {
	if _, err := Load("/nonexistent/path/to/config.ini", nil); err == nil {
		t.Fatalf("expected error for missing explicit --config path")
	}
}

// TestExplicitConfigFileFormats verifies that an explicit --config path loads
// correctly regardless of format: the file's extension selects the codec.
func TestExplicitConfigFileFormats(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		contents string
	}{
		{"ini", "config.ini", "[gateway]\nworker_threads = 7\n\n[logging]\nlevel = WARN\n"},
		{"yaml", "config.yaml", "gateway:\n  worker_threads: 7\nlogging:\n  level: WARN\n"},
		{"yml", "config.yml", "gateway:\n  worker_threads: 7\nlogging:\n  level: WARN\n"},
		{"json", "config.json", `{"gateway":{"worker_threads":7},"logging":{"level":"WARN"}}`},
		{"toml", "config.toml", "[gateway]\nworker_threads = 7\n[logging]\nlevel = \"WARN\"\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tt.filename)
			if err := os.WriteFile(path, []byte(tt.contents), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path, nil)
			if err != nil {
				t.Fatalf("Load(%s) error: %v", tt.filename, err)
			}
			if cfg.Gateway.WorkerThreads != 7 {
				t.Errorf("worker_threads = %d, want 7 (from %s)", cfg.Gateway.WorkerThreads, tt.filename)
			}
			if cfg.Logging.Level != "WARN" {
				t.Errorf("logging.level = %q, want WARN (from %s)", cfg.Logging.Level, tt.filename)
			}
		})
	}
}

// TestSearchConfigFileNonINI verifies that search mode (no --config) discovers a
// non-INI config.<ext> on the search path and infers its codec from the extension.
func TestSearchConfigFileNonINI(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("gateway:\n  worker_threads: 5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Gateway.WorkerThreads != 5 {
		t.Errorf("worker_threads = %d, want 5 (from discovered config.yaml)", cfg.Gateway.WorkerThreads)
	}
}

// TestUnsupportedConfigFileFormatErrors verifies that an explicit --config path
// with an unrecognized or missing extension is rejected (viper returns
// UnsupportedConfigError before decoding).
func TestUnsupportedConfigFileFormatErrors(t *testing.T) {
	for _, name := range []string{"config.conf", "config.xml", "config"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), name)
			if err := os.WriteFile(path, []byte("[gateway]\nworker_threads = 7\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, nil); err == nil {
				t.Fatalf("expected error for unsupported config format %q", name)
			}
		})
	}
}

func TestValidateStartFromNewestXorOffset(t *testing.T) {
	tests := []struct {
		name            string
		startFromNewest bool
		offset          uint64
		wantErr         bool
	}{
		{"both defaults ok", false, 0, false},
		{"newest only ok", true, 0, false},
		{"offset only ok", false, 100, false},
		{"conflict", true, 100, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validGenericConfig()
			cfg.Events.StartFromNewest = tt.startFromNewest
			cfg.Events.Offset = tt.offset
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateFullValidGenericPasses(t *testing.T) {
	cfg := validGenericConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid GENERIC config failed validation: %v", err)
	}
}

func TestValidateAccumulatesErrors(t *testing.T) {
	cfg := validGenericConfig()
	cfg.Gateway.WorkerThreads = 0     // invalid
	cfg.Falcon.CloudRegion = "mars-1" // invalid
	cfg.Events.SeverityThreshold = 9  // invalid
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("expected accumulated validation errors")
	}
}

func TestValidateBackendSubset(t *testing.T) {
	cfg := validGenericConfig()
	cfg.Backends = []string{"GENERIC", "BOGUS"}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error for unrecognized backend")
	}

	empty := validGenericConfig()
	empty.Backends = nil
	if err := empty.Validate(); err == nil {
		t.Fatalf("expected error for empty backends")
	}
}

func TestEnrichDefaults(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Enrich.CacheSize != 8192 {
		t.Errorf("enrich.cache_size = %d, want 8192", cfg.Enrich.CacheSize)
	}
	if cfg.Enrich.CacheTTL != "1h" {
		t.Errorf("enrich.cache_ttl = %q, want 1h", cfg.Enrich.CacheTTL)
	}
	if cfg.Enrich.CacheTTLDuration != time.Hour {
		t.Errorf("enrich.CacheTTLDuration = %v, want 1h", cfg.Enrich.CacheTTLDuration)
	}
}

func TestEnrichEnvOverride(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	t.Setenv("ENRICH_CACHE_SIZE", "256")
	t.Setenv("ENRICH_CACHE_TTL", "30m")

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Enrich.CacheSize != 256 {
		t.Errorf("enrich.cache_size = %d, want 256 (env override)", cfg.Enrich.CacheSize)
	}
	if cfg.Enrich.CacheTTL != "30m" {
		t.Errorf("enrich.cache_ttl = %q, want 30m (env override)", cfg.Enrich.CacheTTL)
	}
	if cfg.Enrich.CacheTTLDuration != 30*time.Minute {
		t.Errorf("enrich.CacheTTLDuration = %v, want 30m (env override)", cfg.Enrich.CacheTTLDuration)
	}
}

func TestValidateEnrich(t *testing.T) {
	tests := []struct {
		name      string
		cacheSize int
		cacheTTL  string
		wantErr   bool
	}{
		{"valid defaults", 8192, "1h", false},
		{"min size ok", 1, "0s", false},
		{"max size ok", 1_000_000, "24h", false},
		{"size zero", 0, "1h", true},
		{"size too large", 1_000_001, "1h", true},
		{"ttl garbage", 8192, "garbage", true},
		{"ttl negative", 8192, "-5m", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validGenericConfig()
			cfg.Enrich.CacheSize = tt.cacheSize
			cfg.Enrich.CacheTTL = tt.cacheTTL
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("expected validation error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestValidateCloudRegions(t *testing.T) {
	tests := []struct {
		region  string
		wantErr bool
	}{
		{"autodiscover", false},
		{"us-1", false},
		{"us-2", false},
		{"us-3", false},
		{"eu-1", false},
		{"us-gov-1", false},
		{"us-gov-2", false},
		{"", true},
		{"mars-1", true},
		{"US-1", true}, // case-sensitive; gofalcon normalizes but validation does not
	}
	for _, tt := range tests {
		t.Run(tt.region, func(t *testing.T) {
			cfg := validGenericConfig()
			cfg.Falcon.CloudRegion = tt.region
			err := cfg.Validate()
			if tt.wantErr && err == nil {
				t.Fatalf("region %q: expected validation error", tt.region)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("region %q: unexpected validation error: %v", tt.region, err)
			}
		})
	}
}

// validGenericConfig returns a minimal Config that passes Validate with only
// the GENERIC backend enabled.
func validGenericConfig() *Config {
	return &Config{
		Gateway: GatewayConfig{WorkerThreads: 4},
		Events: EventsConfig{
			SeverityThreshold:      2,
			OlderThanDaysThreshold: 21,
			OffsetStore:            "file",
			DeliveryFailure:        "dlq",
		},
		Logging: LoggingConfig{Level: "INFO"},
		Falcon: FalconConfig{
			CloudRegion:         "us-1",
			ApplicationID:       "fig-default-app-id",
			ReconnectRetryCount: 36,
		},
		Generic:  GenericConfig{EventTypes: "ALL"},
		Enrich:   EnrichConfig{CacheSize: 8192, CacheTTL: "1h"},
		Backends: []string{"GENERIC"},
	}
}

// chdir switches to dir for the duration of the test and restores the prior
// working directory afterwards.
func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
