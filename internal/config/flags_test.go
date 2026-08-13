package config

import (
	"fmt"
	"slices"
	"testing"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

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
		"--enrich-cache-size=256",
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
	if cfg.Enrich.CacheSize != 256 {
		t.Errorf("enrich.cache_size = %d, want 256", cfg.Enrich.CacheSize)
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
