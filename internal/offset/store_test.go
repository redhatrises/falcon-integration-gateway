package offset

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// storeFactory builds a fresh Store for the shared behavioral tests.
type storeFactory func(t *testing.T) Store

// storeFactories returns a fresh-Store constructor per implementation, shared by
// the table-driven tests that must run against both memory and file stores.
func storeFactories() map[string]storeFactory {
	return map[string]storeFactory{
		"memory": func(_ *testing.T) Store { return NewMemory() },
		"file": func(t *testing.T) Store {
			s, err := NewFile(filepath.Join(t.TempDir(), "offsets.json"))
			if err != nil {
				t.Fatalf("NewFile: %v", err)
			}
			return s
		},
	}
}

func TestStoreBehaviors(t *testing.T) {
	factories := storeFactories()

	for name, factory := range factories {
		t.Run(name+"/load_empty_is_zero", func(t *testing.T) {
			s := factory(t)
			defer s.Close(context.Background())
			got, err := s.Load(context.Background(), "feed-absent")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if got != 0 {
				t.Fatalf("empty Load = %d, want 0", got)
			}
		})

		t.Run(name+"/commit_then_load", func(t *testing.T) {
			s := factory(t)
			defer s.Close(context.Background())
			ctx := context.Background()
			if err := s.Commit(ctx, "feed-a", 42); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if err := s.Commit(ctx, "feed-b", 7); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if got, _ := s.Load(ctx, "feed-a"); got != 42 {
				t.Fatalf("Load feed-a = %d, want 42", got)
			}
			if got, _ := s.Load(ctx, "feed-b"); got != 7 {
				t.Fatalf("Load feed-b = %d, want 7", got)
			}
			// Overwrite advances.
			if err := s.Commit(ctx, "feed-a", 100); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if got, _ := s.Load(ctx, "feed-a"); got != 100 {
				t.Fatalf("Load feed-a after overwrite = %d, want 100", got)
			}
		})

		t.Run(name+"/commit_is_monotonic", func(t *testing.T) {
			s := factory(t)
			defer s.Close(context.Background())
			ctx := context.Background()

			if err := s.Commit(ctx, "feed-a", 100); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			// A lower commit (stale/out-of-order) must not regress the floor.
			if err := s.Commit(ctx, "feed-a", 50); err != nil {
				t.Fatalf("Commit lower: %v", err)
			}
			if got, _ := s.Load(ctx, "feed-a"); got != 100 {
				t.Fatalf("Load feed-a after lower commit = %d, want 100 (monotonic)", got)
			}
			// An equal commit is a no-op and keeps the floor.
			if err := s.Commit(ctx, "feed-a", 100); err != nil {
				t.Fatalf("Commit equal: %v", err)
			}
			if got, _ := s.Load(ctx, "feed-a"); got != 100 {
				t.Fatalf("Load feed-a after equal commit = %d, want 100", got)
			}
			// A higher commit still advances.
			if err := s.Commit(ctx, "feed-a", 101); err != nil {
				t.Fatalf("Commit higher: %v", err)
			}
			if got, _ := s.Load(ctx, "feed-a"); got != 101 {
				t.Fatalf("Load feed-a after higher commit = %d, want 101", got)
			}
		})
	}
}

func TestFilePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "offsets.json")

	s1, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := s1.Commit(ctx, "feed-a", 555); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s1.Commit(ctx, "feed-b", 12); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s1.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := NewFile(path)
	if err != nil {
		t.Fatalf("reopen NewFile: %v", err)
	}
	defer s2.Close(ctx)
	if got, _ := s2.Load(ctx, "feed-a"); got != 555 {
		t.Fatalf("after reopen Load feed-a = %d, want 555", got)
	}
	if got, _ := s2.Load(ctx, "feed-b"); got != 12 {
		t.Fatalf("after reopen Load feed-b = %d, want 12", got)
	}
}

func TestFileDebouncedCommitFlushedOnClose(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "offsets.json")

	s, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	// Two rapid commits: the first persists (lastFlush is zero), the second is
	// debounced within flushInterval and must be flushed by Close.
	if err := s.Commit(ctx, "feed-a", 1); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Commit(ctx, "feed-a", 2); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := NewFile(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close(ctx)
	if got, _ := reopened.Load(ctx, "feed-a"); got != 2 {
		t.Fatalf("debounced value not flushed on Close: got %d, want 2", got)
	}
}

func TestFileAtomicWriteLeavesNoTmp(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "offsets.json")

	s, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	for i := uint64(0); i < 5; i++ {
		if err := s.Commit(ctx, "feed-a", i); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("stray .tmp file present: stat err = %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Fatalf("found leftover tmp file %q", e.Name())
		}
	}
}

func TestFileCommitAfterCloseErrors(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "offsets.json")
	s, err := NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Commit(ctx, "feed-a", 1); err == nil {
		t.Fatal("Commit after Close = nil error, want error")
	}
}

func TestConcurrentCommits(t *testing.T) {
	factories := storeFactories()

	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			s := factory(t)
			defer s.Close(context.Background())
			ctx := context.Background()

			const goroutines = 16
			const perG = 200
			var wg sync.WaitGroup
			wg.Add(goroutines)
			for g := 0; g < goroutines; g++ {
				feed := "feed-" + string(rune('A'+g%4))
				go func(feed string) {
					defer wg.Done()
					for i := 0; i < perG; i++ {
						if err := s.Commit(ctx, feed, uint64(i)); err != nil {
							t.Errorf("Commit: %v", err)
							return
						}
						_, _ = s.Load(ctx, feed)
					}
				}(feed)
			}
			wg.Wait()
		})
	}
}
