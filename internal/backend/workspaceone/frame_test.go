package workspaceone

import (
	"strings"
	"testing"
	"time"
)

func TestFrame(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 8, 14, 12, 30, 45, 0, time.UTC)

	tests := []struct {
		name string
		in   frameInput
		want string
	}{
		{
			name: "standard record: PRI, formatter prefix, padding, trailing NUL",
			in:   frameInput{cef: "CEF:0|x", now: fixedNow, threadName: "fig"},
			// "<14>" + "2026-08-14 12:30:45 ws1 " + threadName(width 10) + " " +
			// "INFO"(width 8) + " " + cef + NUL.
			want: "<14>2026-08-14 12:30:45 ws1 fig" + strings.Repeat(" ", 8) +
				"INFO" + strings.Repeat(" ", 5) + "CEF:0|x\x00",
		},
		{
			name: "thread name longer than 10 is not truncated",
			in:   frameInput{cef: "CEF:0|x", now: fixedNow, threadName: "verylongname"},
			want: "<14>2026-08-14 12:30:45 ws1 verylongname INFO     CEF:0|x\x00",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := string(frame(tt.in))
			if got != tt.want {
				t.Errorf("frame() mismatch\n got: %q\nwant: %q", got, tt.want)
			}
		})
	}
}

func TestFrameEndsWithNUL(t *testing.T) {
	t.Parallel()
	got := frame(frameInput{cef: "CEF:0|x", now: time.Unix(0, 0).UTC(), threadName: "fig"})
	if len(got) == 0 || got[len(got)-1] != 0x00 {
		t.Fatalf("frame() must end with a NUL byte, got %q", got)
	}
	if !strings.HasPrefix(string(got), "<14>") {
		t.Errorf("frame() must start with the syslog PRI <14>, got %q", got)
	}
}
