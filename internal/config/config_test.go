package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
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
	if cfg.WorkspaceOne.TLSVerify {
		t.Errorf("workspaceone.tls_verify = true, want false (parity default)")
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

// TestFalconCloudRegionAlias verifies both the primary FALCON_CLOUD name and the
// legacy FALCON_CLOUD_REGION alias bind to falcon.cloud, and that the primary
// name wins when both are set.
func TestFalconCloudRegionAlias(t *testing.T) {
	t.Run("primary name", func(t *testing.T) {
		chdir(t, t.TempDir())
		t.Setenv("FALCON_CLOUD", "us-2")
		cfg, err := Load("", nil)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.Falcon.CloudRegion != "us-2" {
			t.Errorf("falcon.cloud = %q, want us-2", cfg.Falcon.CloudRegion)
		}
	})

	t.Run("legacy alias", func(t *testing.T) {
		chdir(t, t.TempDir())
		t.Setenv("FALCON_CLOUD_REGION", "eu-1")
		cfg, err := Load("", nil)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.Falcon.CloudRegion != "eu-1" {
			t.Errorf("falcon.cloud = %q, want eu-1 (FALCON_CLOUD_REGION alias)", cfg.Falcon.CloudRegion)
		}
	})

	t.Run("primary beats alias", func(t *testing.T) {
		chdir(t, t.TempDir())
		t.Setenv("FALCON_CLOUD", "us-1")
		t.Setenv("FALCON_CLOUD_REGION", "us-2")
		cfg, err := Load("", nil)
		if err != nil {
			t.Fatalf("Load() error: %v", err)
		}
		if cfg.Falcon.CloudRegion != "us-1" {
			t.Errorf("falcon.cloud = %q, want us-1 (FALCON_CLOUD takes precedence)", cfg.Falcon.CloudRegion)
		}
	})
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

func TestCacheDefaults(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Cache.Size != 8192 {
		t.Errorf("cache.size = %d, want 8192", cfg.Cache.Size)
	}
	if cfg.Cache.TTL != "1h" {
		t.Errorf("cache.ttl = %q, want 1h", cfg.Cache.TTL)
	}
	if cfg.Cache.TTLDuration != time.Hour {
		t.Errorf("cache.TTLDuration = %v, want 1h", cfg.Cache.TTLDuration)
	}
}

func TestCacheEnvOverride(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	t.Setenv("CACHE_SIZE", "256")
	t.Setenv("CACHE_TTL", "30m")

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.Cache.Size != 256 {
		t.Errorf("cache.size = %d, want 256 (env override)", cfg.Cache.Size)
	}
	if cfg.Cache.TTL != "30m" {
		t.Errorf("cache.ttl = %q, want 30m (env override)", cfg.Cache.TTL)
	}
	if cfg.Cache.TTLDuration != 30*time.Minute {
		t.Errorf("cache.TTLDuration = %v, want 30m (env override)", cfg.Cache.TTLDuration)
	}
}

func TestWorkspaceOneTLSVerifyEnvOverride(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	t.Setenv("WORKSPACEONE_TLS_VERIFY", "true")

	cfg, err := Load("", nil)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !cfg.WorkspaceOne.TLSVerify {
		t.Errorf("workspaceone.tls_verify = false, want true (env override)")
	}
}

func TestValidateCache(t *testing.T) {
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
			cfg.Cache.Size = tt.cacheSize
			cfg.Cache.TTL = tt.cacheTTL
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
		{"gov1", false},
		{"gov2", false},
		{"", false},     // empty is accepted as autodiscover by falcon.CloudValidate
		{"US-1", false}, // falcon.CloudValidate normalizes case and dashes
		{"mars-1", true},
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
			DeliveryFailure:        "drop",
		},
		Logging: LoggingConfig{Level: "INFO"},
		Falcon: FalconConfig{
			CloudRegion:         "us-1",
			ApplicationID:       "fig-default-app-id",
			ReconnectRetryCount: 36,
		},
		Generic:  GenericConfig{EventTypes: "ALL"},
		Cache:    CacheConfig{Size: 8192, TTL: "1h"},
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

// newFlagSet returns a flag set with the full config catalog registered, as the
// cobra root command does before Load binds it.
func newFlagSet(t *testing.T) *pflag.FlagSet {
	t.Helper()
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	RegisterFlags(fs)
	return fs
}

// loadWithFlags parses args into a freshly registered flag set and loads config
// from a temp CWD (no config file), so only flags/env/defaults are in play.
func loadWithFlags(t *testing.T, args ...string) *Config {
	t.Helper()
	chdir(t, t.TempDir())
	fs := newFlagSet(t)
	if err := fs.Parse(args); err != nil {
		t.Fatalf("Parse(%v) error: %v", args, err)
	}
	cfg, err := Load("", fs)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	return cfg
}

func TestFlagsSetTypedFields(t *testing.T) {
	cfg := loadWithFlags(t,
		"--worker-threads=9",
		"--falcon-cloud=us-2",
		"--start-from-newest",
		"--offset=123",
		"--aws-confirm-instance=false",
		"--cache-size=256",
		"--backends=AWS,GENERIC",
	)

	if cfg.Gateway.WorkerThreads != 9 {
		t.Errorf("worker_threads = %d, want 9", cfg.Gateway.WorkerThreads)
	}
	if cfg.Falcon.CloudRegion != "us-2" {
		t.Errorf("cloud = %q, want us-2", cfg.Falcon.CloudRegion)
	}
	if !cfg.Events.StartFromNewest {
		t.Errorf("start_from_newest = false, want true")
	}
	if cfg.Events.Offset != 123 {
		t.Errorf("offset = %d, want 123", cfg.Events.Offset)
	}
	if cfg.AWS.ConfirmInstance {
		t.Errorf("aws.confirm_instance = true, want false")
	}
	if cfg.Cache.Size != 256 {
		t.Errorf("cache.size = %d, want 256", cfg.Cache.Size)
	}
	// Derived slice field is computed from the flag-provided string.
	if want := []string{"AWS", "GENERIC"}; !slices.Equal(cfg.Backends, want) {
		t.Errorf("Backends = %v, want %v", cfg.Backends, want)
	}
}

func TestChangedFlagBeatsEnv(t *testing.T) {
	t.Setenv("FIG_WORKER_THREADS", "5")
	cfg := loadWithFlags(t, "--worker-threads=9")
	if cfg.Gateway.WorkerThreads != 9 {
		t.Errorf("worker_threads = %d, want 9 (flag beats env)", cfg.Gateway.WorkerThreads)
	}
}

func TestUnchangedFlagYieldsEnv(t *testing.T) {
	t.Setenv("FIG_WORKER_THREADS", "5")
	cfg := loadWithFlags(t) // flag registered but not set
	if cfg.Gateway.WorkerThreads != 5 {
		t.Errorf("worker_threads = %d, want 5 (env, flag unchanged)", cfg.Gateway.WorkerThreads)
	}
}

func TestUnsetFlagYieldsDefault(t *testing.T) {
	cfg := loadWithFlags(t) // neither flag nor env
	if cfg.Gateway.WorkerThreads != 4 {
		t.Errorf("worker_threads = %d, want 4 (default)", cfg.Gateway.WorkerThreads)
	}
}

func TestSettingsCatalogInvariants(t *testing.T) {
	seenKey := map[string]bool{}
	for _, s := range settings {
		if s.Key == "" {
			t.Errorf("setting has empty Key: %+v", s)
		}
		if seenKey[s.Key] {
			t.Errorf("duplicate Key %q", s.Key)
		}
		seenKey[s.Key] = true

		if s.Flag == "" {
			continue
		}
		switch s.Default.(type) {
		case string, int, uint64, bool:
		default:
			t.Errorf("setting %q has unsupported Default type %T", s.Key, s.Default)
		}
	}
}

// TestEverySettingHasValidGroup protects the data-driven contract: any setting
// that defines a Flag must name a group in groupOrder, so a newly added flag
// can't silently fall into the RegisterFlags catch-all bucket.
func TestEverySettingHasValidGroup(t *testing.T) {
	valid := map[string]bool{}
	for _, g := range groupOrder {
		valid[g] = true
	}
	for _, s := range settings {
		if s.Flag == "" {
			continue
		}
		if !valid[s.Group] {
			t.Errorf("flag %q has group %q not in groupOrder %v", s.Flag, s.Group, groupOrder)
		}
	}
}

// TestRegisterFlagsGroups verifies RegisterFlags returns groups in groupOrder
// (no catch-all appended) and that every catalog flag lands in exactly one
// group and on the command flag set — nothing dropped or duplicated.
func TestRegisterFlagsGroups(t *testing.T) {
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	groups := RegisterFlags(fs)

	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	if !slices.Equal(names, groupOrder) {
		t.Fatalf("group names = %v, want %v", names, groupOrder)
	}

	want := 0
	for _, s := range settings {
		if s.Flag != "" {
			want++
		}
	}

	seen := map[string]int{}
	total := 0
	for _, g := range groups {
		g.FlagSet.VisitAll(func(f *pflag.Flag) {
			seen[f.Name]++
			total++
		})
	}
	if total != want {
		t.Errorf("grouped flag count = %d, want %d", total, want)
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("flag %q appears in %d groups, want 1", name, n)
		}
		if fs.Lookup(name) == nil {
			t.Errorf("flag %q not added to command flag set", name)
		}
	}
}

// TestFlagDefaultMatchesViperDefault guards the single-source-of-truth claim:
// each registered flag's default string must equal the viper SetDefault value
// for the same key, so --help and precedence resolution stay consistent.
func TestFlagDefaultMatchesViperDefault(t *testing.T) {
	fs := newFlagSet(t)
	v := viper.New()
	setDefaults(v)

	for _, s := range settings {
		if s.Flag == "" {
			continue
		}
		flag := fs.Lookup(s.Flag)
		if flag == nil {
			t.Errorf("flag %q not registered for key %q", s.Flag, s.Key)
			continue
		}
		if got, want := flag.DefValue, fmt.Sprint(v.Get(s.Key)); got != want {
			t.Errorf("key %q: flag default %q != viper default %q", s.Key, got, want)
		}
	}
}
