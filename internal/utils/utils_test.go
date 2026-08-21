package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSleep(t *testing.T) {
	t.Parallel()

	cancelled := func() context.Context {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	}

	tests := []struct {
		name string
		ctx  context.Context
		d    time.Duration
		want bool
	}{
		{"non-positive duration, live ctx", context.Background(), 0, true},
		{"negative duration, live ctx", context.Background(), -time.Second, true},
		{"non-positive duration, cancelled ctx", cancelled(), 0, false},
		{"positive duration elapses", context.Background(), time.Millisecond, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := Sleep(tt.ctx, tt.d); got != tt.want {
				t.Fatalf("Sleep() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSleepCancelledDuringWait(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	if Sleep(ctx, time.Hour) {
		t.Fatal("Sleep() = true, want false when ctx cancelled before duration elapses")
	}
}

func TestIsCanceled(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"context.Canceled", context.Canceled, true},
		{"context.DeadlineExceeded", context.DeadlineExceeded, true},
		{"wrapped Canceled", fmt.Errorf("wrap: %w", context.Canceled), true},
		{"unrelated error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsCanceled(tt.err); got != tt.want {
				t.Fatalf("IsCanceled(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestSplitCSV(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"whitespace only", "   ", nil},
		{"single", "AWS", []string{"AWS"}},
		{"trims spaces", " AWS , GCP ", []string{"AWS", "GCP"}},
		{"drops empties and trailing comma", "AWS,,GCP,", []string{"AWS", "GCP"}},
		{"leading comma", ",AWS", []string{"AWS"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SplitCSV(tt.in)
			if len(got) != len(tt.want) {
				t.Fatalf("SplitCSV(%q) = %v, want %v", tt.in, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("SplitCSV(%q) = %v, want %v", tt.in, got, tt.want)
				}
			}
		})
	}
}

func TestIntFromAny(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   any
		want int
	}{
		{"float64 truncates", float64(3.9), 3},
		{"int passes through", 7, 7},
		{"json.Number integer literal", json.Number("42"), 42},
		{"json.Number decimal literal truncates", json.Number("3.0"), 3},
		{"json.Number fractional truncates toward zero", json.Number("9.99"), 9},
		{"json.Number beyond 2^53 is exact", json.Number("9007199254740993"), 9007199254740993},
		{"json.Number garbage is zero", json.Number("not-a-number"), 0},
		{"string is zero", "5", 0},
		{"nil is zero", nil, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IntFromAny(tc.in); got != tc.want {
				t.Errorf("IntFromAny(%v) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
