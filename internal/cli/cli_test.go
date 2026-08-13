package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestRootHelpGroupsInOrder runs `fig --help` and asserts every flag-group
// heading is present and rendered in the expected order, plus the Global Flags
// section. This locks in the grouped --help layout set up by setGroupedHelp.
func TestRootHelpGroupsInOrder(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(--help) error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Global Flags:") {
		t.Errorf("help output missing Global Flags section:\n%s", out)
	}

	headings := []string{
		"Gateway & Runtime:",
		"Event Filtering & Offsets:",
		"Falcon API:",
		"Credential Stores:",
		"Backends:",
		"Enrichment:",
	}
	last := -1
	for _, h := range headings {
		i := strings.Index(out, h)
		if i < 0 {
			t.Errorf("help output missing heading %q", h)
			continue
		}
		if i < last {
			t.Errorf("heading %q appears out of order", h)
		}
		last = i
	}
}

// TestVersionSubcommandHelpUnaffected confirms the identity guard in
// setGroupedHelp: a subcommand keeps cobra's stock flat rendering rather than
// the root's grouped output.
func TestVersionSubcommandHelpUnaffected(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"version", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute(version --help) error: %v", err)
	}

	out := buf.String()
	if strings.Contains(out, "Gateway & Runtime:") {
		t.Errorf("version --help leaked root flag groups:\n%s", out)
	}
	if !strings.Contains(out, "Flags:") {
		t.Errorf("version --help missing stock Flags section:\n%s", out)
	}
}
