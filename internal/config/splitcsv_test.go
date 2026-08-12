package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/spf13/viper"
)

// TestSplitCSVSemantics pins the trim + drop-empty + ""->nil behavior that
// splitCSV provides and that neither viper path reproduces.
func TestSplitCSVSemantics(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"plain", "AWS,GENERIC", []string{"AWS", "GENERIC"}},
		{"trims surrounding space", "AWS, GENERIC", []string{"AWS", "GENERIC"}},
		{"drops empty tokens", "AWS,,GENERIC", []string{"AWS", "GENERIC"}},
		{"trailing comma", "AWS,", []string{"AWS"}},
		{"whitespace only is nil", "  ", nil},
		{"empty is nil", "", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitCSV(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitCSV(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

// TestConfigFileCSVTrimming verifies the realistic source of a spaced CSV
// value: a config file, where `backends = AWS, GENERIC` is idiomatic and no
// shell is involved to split on the space. This is where splitCSV's trimming
// actually earns its keep.
func TestConfigFileCSVTrimming(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.ini")
	contents := "[main]\nbackends = AWS, GENERIC\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	// The raw unmarshalled string carries the space; splitCSV removes it.
	if want := []string{"AWS", "GENERIC"}; !reflect.DeepEqual(cfg.Backends, want) {
		t.Errorf("cfg.Backends = %#v, want %#v (trimmed)", cfg.Backends, want)
	}
}

// slice handling comma-splits (on Unmarshal) but does not trim, and whitespace-
// splits (on the GetStringSlice accessor path) without comma-splitting at all.
func TestViperSliceHookContrast(t *testing.T) {
	// Unmarshal path: viper's stringToWeakSliceHookFunc comma-splits but leaves
	// the surrounding space, so " GENERIC" would never match a backend name.
	v := viper.New()
	v.Set("k", "AWS, GENERIC")
	var out struct {
		K []string `mapstructure:"k"`
	}
	if err := v.Unmarshal(&out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if want := []string{"AWS", " GENERIC"}; !reflect.DeepEqual(out.K, want) {
		t.Errorf("viper Unmarshal []string = %#v, want %#v (untrimmed)", out.K, want)
	}
	// splitCSV on the same input trims, which is what the code needs.
	if got, want := splitCSV("AWS, GENERIC"), []string{"AWS", "GENERIC"}; !reflect.DeepEqual(got, want) {
		t.Errorf("splitCSV = %#v, want %#v", got, want)
	}

	// Accessor path: viper.GetStringSlice delegates to cast.ToStringSlice, which
	// splits on whitespace, never commas, so a CSV value collapses to a single
	// element.
	v.Set("csv", "AWS,GENERIC")
	if got, want := v.GetStringSlice("csv"), []string{"AWS,GENERIC"}; !reflect.DeepEqual(got, want) {
		t.Errorf("viper.GetStringSlice = %#v, want %#v (one element)", got, want)
	}
}
