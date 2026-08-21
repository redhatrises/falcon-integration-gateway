# Developer Guide

The Falcon Integration Gateway (FIG) is a long-running Go daemon that consumes the
CrowdStrike Falcon Event Streams API and forwards detection findings and audit events to
one or more third-party backends. It is a single binary (`cmd/fig`), not a library or a
web service.

## Architecture

At its core FIG is a bounded, backpressured pipeline with **one producer** (the stream
supervisor) and **N concurrent consumers** (the pipeline workers), connected by a single
buffered channel:

```
Falcon Event Streams API
   → stream.Supervisor            [producer: one long-poll connection per partition]
   → chan *events.Event           [bounded; a full channel backpressures the reader]
   → pipeline workers × N         [consumers: enrich → gate → deliver → commit]
   → backend.Backend.Process      [each enabled backend]
```

Read [cmd/fig/main.go](../cmd/fig/main.go) and then [internal/cli/run.go](../internal/cli/run.go)
first: `main` hands a root context to the cobra command tree, and `cli.run` wires every
component together under a single `errgroup` whose lifetimes are driven by a
signal-cancellable context (the Go analog of the old Python `fig/__main__.py`).

### Producer — `internal/falcon/stream`

`Supervisor` lists the application's event streams, opens one long-poll connection per
stream partition, keeps each session refreshed, and rebuilds the whole session whenever
any connection closes. Instead of the Python supervisor's `sys.exit(1)` on failure, it
retries forever with a capped exponential backoff, resetting the backoff only after a
session stays up past `healthyRunThreshold`.

Offset resumption is resolved per connection by `resolveOffset(configOffset, queueOffset,
startFromNewest)`, which returns `max(configOffset, queueOffset)` and a `useWhence` flag.
`whence=2` (start from newest) is only honored on a feed's first-ever connection with no
persisted or configured offset; reconnections resume from the stored watermark so events
are not re-delivered. On a feed's first connection the supervisor seeds the pipeline's
commit-watermark floor to `firstOffset-1` so a cold start (or an aged-out resume) can
advance.

### Consumer — `internal/pipeline`

`Pipeline.Run` drains the event channel with a bounded worker pool. Each event flows
through: enrichment → three dispatch gates (event-type acceptance → cloud-detection
relevance → per-backend `IsRelevant`) → delivery to each passing backend → offset commit.

The `commitTracker` ([internal/pipeline/tracker.go](../internal/pipeline/tracker.go)) is
the crux of **at-least-once** delivery: workers complete out of order, but an offset is
only committed once every received offset up to and including it has completed. It advances
the watermark over server-side filter gaps (offsets belonging to filtered-out event types
never arrive) without stalling. Two debounce layers — the tracker's in-order gate and the
offset store's time-coalesced flush — mean an abrupt crash re-delivers events after the
last durably persisted floor; every backend must therefore be idempotent or dedupe on the
carried key. See the `commitTracker` doc comment for the precise crash-loss window.

### Event model & enrichment — `internal/events`, `internal/enrich`

`events.Event` wraps the raw stream JSON and normalizes the two event families (detection
and audit) behind single accessors, plus `EventID()` (the real detection/audit id) and
`DedupKey()` (`<feedID>_<offset>`). `enrich.Resolver` resolves per-sensor host details and
MDM identifiers from the Hosts and RTR APIs, caching results in a bounded, TTL'd
single-flight cache so concurrent workers touch the network at most once per sensor.

### Offset store — `internal/offset`

`Store` implementations persist the per-feed resume watermark. `file` (default) writes an
atomic JSON file, `ssm` persists to an AWS SSM parameter, and `memory` is ephemeral for
tests. The durable stores embed a `BufferedStore` that advances in memory immediately but
coalesces the disk/SSM write to at most once per flush interval, with a guaranteed final
flush on `Close`.

## Backend contract

Each backend is a package under [internal/backend/](../internal/backend/) that registers a
constructor with the backend registry from its `init()`. A backend implements
`backend.Backend`: `Name()`, `RelevantEventTypes()`, `IsRelevant(event)`, and
`Process(ctx, event)`. `RelevantEventTypes()` also feeds the producer: the union across
enabled backends becomes the server-side `&eventType=` filter, so a backend that narrows
its types reduces what Falcon sends (if any backend declares `"ALL"`, no filter is applied).

Wiring a new backend requires: (1) the package with its `init()` registration, (2) a
blank import in [internal/cli/run.go](../internal/cli/run.go), and (3) the backend name in
the config's valid-backend set. A test asserts the config set matches `backend.Names()`.

## Getting Started

Building FIG from source requires **Go 1.26 or later** (see [go.mod](../go.mod)). Running a
prebuilt binary or the container image has no such requirement.

### Local workflow

```bash
make build   # gofmt + go vet, then build the ./fig binary
make run      # build and run
make test     # go test -race with coverage
make lint     # golangci-lint
make help     # list all targets
```

Run locally against a Falcon tenant with `FIG_BACKENDS=GENERIC`, which logs each processed
event to stdout — the cheapest way to verify the end-to-end path without a real downstream.

### Container workflow

The container bundles all backend SDK dependencies and is convenient for exercising a
specific backend. Pass config options as environment variables:

```bash
docker build . -t falcon-integration-gateway
docker run -it --rm \
  -e FALCON_CLIENT_ID="$FALCON_CLIENT_ID" \
  -e FALCON_CLIENT_SECRET="$FALCON_CLIENT_SECRET" \
  -e FALCON_CLOUD_REGION="us-1" \
  -e FIG_BACKENDS=<BACKEND> \
  falcon-integration-gateway:latest
```

Most backends have a corresponding developer guide under [docs/](.) with backend-specific
setup and examples.
