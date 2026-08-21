// Package offset implements durable resume-offset storage for the Falcon
// Event Streams pipeline. It replaces the in-memory, at-most-once offset
// tracking in the Python daemon's fig/queue/__init__.py (the FalconEvents
// queue, which stored offsets in a plain dict and advanced them on dequeue).
//
// A Store persists the highest committed offset per Falcon feed_id so that a
// process restart resumes the stream where delivery last succeeded, giving
// at-least-once semantics. Three implementations are provided:
//
//   - Memory: an in-memory map (tests and ephemeral runs); the direct analog
//     of the Python dict but without dequeue-time advancement.
//   - File: an atomically-written JSON object persisted to disk, surviving
//     process restarts.
//   - SSM: the same JSON object persisted to an AWS Systems Manager parameter,
//     surviving restarts without a shared filesystem (stateless containers).
package offset

import (
	"context"
	"sync"
)

// Store persists the highest committed resume offset per Falcon feed_id.
//
// Load returns the last committed offset for feedID, or 0 when none has been
// recorded (0 is a valid "start from beginning" sentinel, not an error).
// Commit records offset for feedID durably. Close flushes any pending state
// and releases resources; it must be safe to call once.
type Store interface {
	Load(ctx context.Context, feedID string) (uint64, error)
	Commit(ctx context.Context, feedID string, offset uint64) error
	Close(ctx context.Context) error
}

// applyOffset stores offset for feedID in offsets iff it advances the resume
// floor, reporting whether the map changed. The watermark is monotonic: a commit
// at or below the current value is rejected so a stale or out-of-order commit
// never regresses it. Callers must hold the store's lock.
func applyOffset(offsets map[string]uint64, feedID string, offset uint64) bool {
	if cur, ok := offsets[feedID]; ok && cur >= offset {
		return false
	}
	offsets[feedID] = offset
	return true
}

// Memory is an in-memory Store backed by a map guarded by a RWMutex. It is the
// direct analog of the Python FalconEvents offset dict
// (fig/queue/__init__.py), minus the at-most-once dequeue-time advancement.
// Offsets do not survive process restarts; use File for durability.
type Memory struct {
	mu      sync.RWMutex
	offsets map[string]uint64
}

// NewMemory returns an empty in-memory offset Store.
func NewMemory() *Memory {
	return &Memory{offsets: make(map[string]uint64)}
}

// Load returns the last committed offset for feedID, or 0 when absent.
func (m *Memory) Load(_ context.Context, feedID string) (uint64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.offsets[feedID], nil
}

// Commit advances feedID's offset in memory. The stored offset is monotonic: a
// commit at or below the current value is a no-op, so a stale or out-of-order
// commit never regresses the resume floor.
func (m *Memory) Commit(_ context.Context, feedID string, offset uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	applyOffset(m.offsets, feedID, offset)
	return nil
}

// Close is a no-op for the in-memory store.
func (m *Memory) Close(_ context.Context) error {
	return nil
}
