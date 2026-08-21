package gcp

import "testing"

func TestFindingID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		eventID       string
		eventCreation int64
		want          string
	}{
		{
			// Non-alphanumeric characters are stripped from the event id, and
			// the last six characters of the hexadecimal creation time are
			// appended. The result is short enough that no clamp applies.
			name:          "strip and suffix, no clamp",
			eventID:       "ab-cd_12",
			eventCreation: 19088743, // 0x1234567
			want:          "abcd12234567",
		},
		{
			// A concatenation longer than 32 characters is clamped to its last
			// 32 characters.
			name:          "clamped to last 32 chars",
			eventID:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 40 x 'a'
			eventCreation: 19088743,                                   // -> 234567
			want:          "aaaaaaaaaaaaaaaaaaaaaaaaaa234567",         // 26 x 'a' + 234567
		},
		{
			// A tiny creation time produces a hex string shorter than six
			// characters, so the "0x" prefix bleeds into the suffix. This
			// documents the intended behavior rather than sanitizing it.
			name:          "small creation time keeps 0x prefix",
			eventID:       "x",
			eventCreation: 255, // hex(255) == "0xff"
			want:          "x0xff",
		},
		{
			// An event id of only non-alphanumeric characters strips to empty,
			// leaving just the creation-time suffix.
			name:          "event id strips to empty",
			eventID:       "!!!",
			eventCreation: 19088743,
			want:          "234567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := findingID(tt.eventID, tt.eventCreation); got != tt.want {
				t.Errorf("findingID(%q, %d) = %q, want %q", tt.eventID, tt.eventCreation, got, tt.want)
			}
		})
	}
}

func TestSeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "informational maps to low", in: "Informational", want: "LOW"},
		{name: "lowercase informational maps to low", in: "informational", want: "LOW"},
		{name: "high uppercases", in: "High", want: "HIGH"},
		{name: "critical uppercases", in: "Critical", want: "CRITICAL"},
		{name: "medium uppercases", in: "Medium", want: "MEDIUM"},
		{name: "empty stays empty", in: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := severity(tt.in); got != tt.want {
				t.Errorf("severity(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
