package utils

import (
	"context"
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
