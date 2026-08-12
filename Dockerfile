# Build stage — Red Hat Hardened Images Go toolchain embeds the validated
# FIPS module in all binaries automatically.
FROM registry.access.redhat.com/hi/go:1.26-fips AS builder

WORKDIR /src

# Version metadata stamped into the binary via ldflags.
ARG VERSION=0.0.0+dev
ARG COMMIT=unknown

# Download modules first so the layer is cached when only source changes.
COPY go.mod go.sum ./
RUN go mod download

# Build the static binary. CGO_ENABLED=0 means the runtime stage needs no C
# libraries. Copy cmd and internal into their own subtrees (a multi-source COPY
# into ./ would flatten each directory's contents and lose the package paths).
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build \
        -trimpath \
        -ldflags "-s -w \
            -X github.com/crowdstrike/falcon-integration-gateway/internal/version.Version=${VERSION} \
            -X github.com/crowdstrike/falcon-integration-gateway/internal/version.Commit=${COMMIT}" \
        -o /src/fig \
        ./cmd/fig

# Runtime stage — minimal hardened base; GODEBUG runs the binary in FIPS mode.
FROM registry.access.redhat.com/hi/core-runtime:latest

COPY --from=builder /src/fig /fig

# Configuration is optional: all defaults live in code (viper.SetDefault), so the
# image ships no INI file. Deployments that need overrides mount a config.ini
# ConfigMap onto the /etc/fig search path, or pass FIG_* environment variables.

# FIPS mode is off by default (GODEBUG empty). The validated FIPS module is
# compiled into the binary regardless, so enabling it is a pure runtime toggle:
# docker run -e GODEBUG=fips140=on ... (values: on, only).
ENV GODEBUG=

# Run as a non-root user. UID 1000 matches the Python image and the
# securityContext in the Helm chart.
USER 1000

ENTRYPOINT ["/fig"]
