// Package cli builds the fig command-line interface: a root command that runs
// the daemon and a version subcommand. It registers a flag for every config
// setting and binds them into config resolution (flag > env > file > default
// precedence) and hands the resolved, validated config to Run, which wires up
// and drives the daemon (see run.go).
//
// The cobra command tree keeps main.go a single Execute call so the Makefile
// (`go run ./cmd/fig/main.go`) and goreleaser (`main: ./cmd/fig/main.go`) still
// build from one file.
package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/crowdstrike/falcon-integration-gateway/internal/config"
	"github.com/crowdstrike/falcon-integration-gateway/internal/version"
)

var (
	progName   = "fig"
	cliVersion = fmt.Sprintf("%s %s <commit: %s>", progName, version.Version, version.Commit)
)

// Execute builds the command tree and runs it, propagating ctx into the daemon.
// It returns the command error for main to translate into an exit code; the
// daemon (Run) installs its own signal-cancellable shutdown.
func Execute(ctx context.Context) error {
	return newRootCmd().ExecuteContext(ctx)
}

// newRootCmd constructs the root fig command and its subcommands. The root
// command runs the daemon; --config is a persistent flag (it selects the config
// file rather than a viper key), and every config setting is registered as a
// local flag so any of them can be overridden on the command line.
func newRootCmd() *cobra.Command {
	var configPath string

	rootCmd := &cobra.Command{
		Use:     progName,
		Short:   "Falcon Integration Gateway",
		Long:    "Falcon Integration Gateway streams CrowdStrike Falcon events to third-party backends.",
		Version: cliVersion,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfig(configPath, cmd.Flags())
			if err != nil {
				return err
			}

			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return Run(cmd.Context(), cfg)
		},
	}

	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "path to a config file (INI, JSON, TOML, or YAML; default: search /etc/fig, ./config, .)")
	groups := config.RegisterFlags(rootCmd.Flags())
	setGroupedHelp(rootCmd, groups)

	rootCmd.AddCommand(newVersionCmd())
	return rootCmd
}

// setGroupedHelp overrides the root command's usage/help output so flags print
// under their group headings instead of one flat, alphabetized list. Cobra
// inherits these funcs down to subcommands, so an identity check falls back to
// cobra's stock rendering for anything other than root (e.g. keeping
// `fig version --help` unchanged).
func setGroupedHelp(root *cobra.Command, groups []config.NamedFlagSet) {
	defaultUsage := root.UsageFunc()
	defaultHelp := root.HelpFunc()

	usage := func(c *cobra.Command) error {
		if c != root {
			return defaultUsage(c)
		}
		w := c.OutOrStderr()

		fmt.Fprintf(w, "Usage:\n  %s\n", c.UseLine())
		if c.HasAvailableSubCommands() {
			fmt.Fprintf(w, "  %s [command]\n", c.CommandPath())
		}
		fmt.Fprintln(w)

		if c.HasAvailableSubCommands() {
			fmt.Fprintln(w, "Available Commands:")
			pad := c.NamePadding()
			for _, sub := range c.Commands() {
				if sub.IsAvailableCommand() || sub.Name() == "help" {
					fmt.Fprintf(w, "  %-*s %s\n", pad, sub.Name(), sub.Short)
				}
			}
			fmt.Fprintln(w)
		}

		if global := globalFlagSet(c); global.HasFlags() {
			fmt.Fprintf(w, "Global Flags:\n%s\n", global.FlagUsages())
		}
		for _, g := range groups {
			if g.FlagSet.HasFlags() {
				fmt.Fprintf(w, "%s:\n%s\n", g.Name, g.FlagSet.FlagUsages())
			}
		}

		if c.HasAvailableSubCommands() {
			fmt.Fprintf(w, "Use \"%s [command] --help\" for more information about a command.\n", c.CommandPath())
		}
		return nil
	}

	root.SetUsageFunc(usage)
	root.SetHelpFunc(func(c *cobra.Command, args []string) {
		if c != root {
			defaultHelp(c, args)
			return
		}
		if c.Long != "" {
			fmt.Fprintf(c.OutOrStdout(), "%s\n\n", c.Long)
		}
		_ = usage(c)
	})
}

// globalFlagSet collects the flags shown under the "Global Flags" heading: the
// persistent --config plus cobra's auto-added --help/--version (initialized here
// so they are present when help renders). SortFlags is off to keep --config
// first.
func globalFlagSet(c *cobra.Command) *pflag.FlagSet {
	c.InitDefaultHelpFlag()
	c.InitDefaultVersionFlag()

	fs := pflag.NewFlagSet("global", pflag.ContinueOnError)
	fs.SortFlags = false
	fs.AddFlagSet(c.PersistentFlags())
	for _, name := range []string{"help", "version"} {
		if f := c.Flags().Lookup(name); f != nil {
			fs.AddFlag(f)
		}
	}
	return fs
}

// loadConfig resolves configuration from the given flag set (highest
// precedence, matching flag > env > file > default), then validates it so
// startup fails fast on bad config.
func loadConfig(configPath string, flags *pflag.FlagSet) (*config.Config, error) {
	cfg, err := config.Load(configPath, flags)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
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
