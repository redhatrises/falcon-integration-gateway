// Package cli builds the fig command-line interface: a root command that runs
// the daemon and a version subcommand. It binds the --config and --log-level
// flags into config resolution (flag > env > file > default precedence) and
// hands the resolved, validated config to internal/app.
//
// It replaces the Python daemon's argparse-free `python -m fig` entry point;
// the cobra command tree keeps main.go a single Execute call so the Makefile
// (`go run ./cmd/fig/main.go`) and goreleaser (`main: ./cmd/fig/main.go`) still
// build from one file.
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/crowdstrike/falcon-integration-gateway/internal/app"
	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/version"
)

var (
	progName   = "fig"
	cliVersion = fmt.Sprintf("%s %s <commit: %s>", progName, version.Version, version.Commit)
)

// Execute builds the command tree and runs it, propagating ctx into the daemon.
// It returns the command error for main to translate into an exit code; the
// daemon (internal/app) installs its own signal-cancellable shutdown.
func Execute(ctx context.Context) error {
	return newRootCmd().ExecuteContext(ctx)
}

// newRootCmd constructs the root fig command and its subcommands. The root
// command runs the daemon; --config and --log-level are persistent flags so
// they apply to the root run.
func newRootCmd() *cobra.Command {
	var (
		configPath string
		logLevel   string
	)

	rootCmd := &cobra.Command{
		Use:           progName,
		Short:         "Falcon Integration Gateway",
		Long:          "Falcon Integration Gateway streams CrowdStrike Falcon events to third-party backends.",
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       cliVersion,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(configPath, logLevel)
			if err != nil {
				return err
			}
			return app.Run(cmd.Context(), cfg)
		},
	}

	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "path to a config file (INI, JSON, TOML, or YAML; default: search /etc/fig, ./config, .)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "", "log level override (DEBUG, INFO, WARN, ERROR)")

	rootCmd.AddCommand(newVersionCmd())
	return rootCmd
}

// loadConfig resolves configuration and applies the --log-level flag override
// (highest precedence, matching the plan's flag > env > file > default order),
// then validates it so startup fails fast on bad config.
func loadConfig(configPath, logLevel string) (*config.Config, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if logLevel != "" {
		cfg.Logging.Level = logLevel
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	return cfg, nil
}

// newVersionCmd prints the ldflags-stamped version and commit.
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and build commit",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Println(cliVersion)
		},
	}
}
