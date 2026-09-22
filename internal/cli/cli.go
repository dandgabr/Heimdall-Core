// Package cli implements the Heimdall command-line interface.
//
// Commands are thin: they resolve configuration, build the app and translate
// errors to a localised message plus a non-zero exit code. No business logic
// lives here.
package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/dandgabr/heimdall-core/internal/app"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// Version is the build version, overridable at link time with
// -ldflags "-X .../internal/cli.Version=x.y.z".
var Version = "dev"

// Execute runs the CLI with the given arguments and returns the process exit
// code, writing command output to os.Stdout and diagnostics to os.Stderr.
func Execute(args []string) int {
	return executeWith(os.Stderr, os.Stdout, args)
}

// executeTo is Execute with an explicit error sink, so tests can assert the
// rendered operator-facing message.
func executeTo(stderr io.Writer, args []string) int {
	return executeWith(stderr, io.Discard, args)
}

// executeToWithStdout is executeTo with a capturable stdout, used by tests that
// assert command output.
func executeToWithStdout(stdout io.Writer, args []string) int {
	return executeWith(os.Stderr, stdout, args)
}

func executeWith(stderr, stdout io.Writer, args []string) int {
	bundle, err := i18n.New()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, i18n.RedactString(err.Error()))
		return 1
	}
	root := newRootCmd()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		// Render the DomainError through the catalog: resolve the code in the
		// CLI's negotiated language and interpolate its named params. This is
		// what surfaces the actionable detail (e.g. the vault path and mode)
		// that err.Error() drops, without ever leaking a secret.
		_, _ = fmt.Fprintln(stderr, bundle.FormatDomainError(err, cliLanguage(bundle)))
		return 1
	}
	return 0
}

// cliLanguage resolves the CLI display language: the process locale (LC_ALL,
// then LANG) negotiated against the embedded catalogs, falling back to en. It
// reuses the same negotiation as the HTTP layer so both agree on precedence.
func cliLanguage(bundle *i18n.Bundle) string {
	preference := os.Getenv("LC_ALL")
	if preference == "" {
		preference = os.Getenv("LANG")
	}
	return bundle.Negotiate("", normalizeLocale(preference))
}

// normalizeLocale converts a POSIX locale ("pt_BR.UTF-8", "en_US.utf8", "C") to
// a BCP-47 tag ("pt-BR", "en-US", "") that golang.org/x/text can parse. The
// POSIX form uses '_' as the separator and often carries an encoding suffix,
// neither of which Parse accepts.
func normalizeLocale(locale string) string {
	if locale == "" || locale == "C" || locale == "POSIX" {
		return ""
	}
	// Drop the encoding: "pt_BR.UTF-8" -> "pt_BR".
	if i := strings.IndexAny(locale, ".@"); i >= 0 {
		locale = locale[:i]
	}
	locale = strings.ReplaceAll(locale, "_", "-")
	return locale
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "heimdall",
		Short:         "Local multi-provider routing and proxy engine",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(newServeCmd(), newVersionCmd(), newTokenCmd(), newProviderCmd())
	return root
}

// serveFlags captures the flag values so only explicitly-set flags enter the
// precedence chain (config.Load).
type serveFlags struct {
	configPath  string
	host        string
	port        int
	allowRemote bool
}

func newServeCmd() *cobra.Command {
	flags := &serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Heimdall gateway and management API",
		RunE: func(cmd *cobra.Command, _ []string) error {
			flagVals := map[string]string{}
			// Only flags the user actually set may override the file.
			for name := range map[string]struct{}{
				"host": {}, "port": {}, "allow-remote": {},
			} {
				if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
					flagVals[name] = f.Value.String()
				}
			}

			cfg, err := config.Load(config.Options{
				FilePath: flags.configPath,
				Flags:    flagVals,
				Env:      environ(),
			})
			if err != nil {
				return err
			}

			instance, err := app.Build(app.Options{
				Config: cfg,
				Env:    environ(),
			})
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return instance.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&flags.configPath, "config", "", "path to the TOML configuration file")
	cmd.Flags().StringVar(&flags.host, "host", config.LoopbackHost, "bind address for the HTTP listener")
	cmd.Flags().IntVar(&flags.port, "port", 8787, "bind port for the HTTP listener")
	cmd.Flags().BoolVar(&flags.allowRemote, "allow-remote", false,
		"allow a non-loopback bind (required to bind anything but loopback)")
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the Heimdall version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), Version)
			return err
		},
	}
}

// newTokenCmd implements `heimdall token rotate`: it issues a new management
// token, stores only its hash and writes the plaintext to the 0600 token file,
// invalidating the previous token. The secret is never printed.
func newTokenCmd() *cobra.Command {
	token := &cobra.Command{
		Use:   "token",
		Short: "Manage the management API token",
	}
	token.AddCommand(newTokenRotateCmd())
	return token
}

func newTokenRotateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "rotate",
		Short: "Rotate the management token (invalidates the previous one)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.Options{
				FilePath: configPath,
				Env:      environ(),
			})
			if err != nil {
				return err
			}

			instance, err := app.Build(app.Options{Config: cfg, Env: environ()})
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			path, err := instance.RotateManagementToken()
			if err != nil {
				return err
			}
			// Report the file path, never the token. The CLI does not log the
			// secret through the structured logger either.
			_, err = fmt.Fprintln(cmd.OutOrStdout(), instance.Bundle.Format(
				cliLanguage(instance.Bundle), domain.CodeTokenRotationOK,
				map[string]string{"path": path}))
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// newProviderCmd groups the read/management provider commands. None of them
// performs network I/O: `list` and `status` only inspect the registry and the
// descriptors, and `import` reads local files (read-only) into the vault.
func newProviderCmd() *cobra.Command {
	provider := &cobra.Command{
		Use:   "provider",
		Short: "Inspect and import provider credentials",
	}
	provider.AddCommand(newProviderListCmd(), newProviderStatusCmd(), newProviderImportCmd())
	return provider
}

func newProviderListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List registered providers, auth modes and pending endpoints",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			out := cmd.OutOrStdout()
			for _, p := range instance.ProviderList() {
				modes := strings.Join(p.AuthModes, ",")
				pending := "ready"
				if len(p.PendingEndpoints) > 0 {
					pending = "pending: " + strings.Join(p.PendingEndpoints, ",")
				}
				if _, err := fmt.Fprintf(out, "%s\tprotocol=%s\tauth=%s\t%s\n",
					p.ID, p.Protocol, modes, pending); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

func newProviderStatusCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Report whether each provider's auth flow can be built now",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			out := cmd.OutOrStdout()
			for _, s := range instance.ProviderStatus() {
				state := "ready"
				if !s.Ready {
					state = "blocked"
					if s.ReasonCode != "" {
						state = "blocked(" + s.ReasonCode + ")"
					}
				}
				if _, err := fmt.Fprintf(out, "%s\t%s\n", s.ID, state); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

func newProviderImportCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import credentials from local harness files (read-only, sealed into the vault)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			results, err := instance.ImportCredentials(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(results) == 0 {
				_, err := fmt.Fprintln(out, "no importable credentials found")
				return err
			}
			for _, r := range results {
				// Report the id and label only; never the value.
				if _, err := fmt.Fprintf(out, "%s\tprovider=%s\tlabel=%s\n",
					r.CredentialID, r.Provider, r.Label); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// buildReadOnly loads the config and builds the app for a management command
// that does not start the listener.
func buildReadOnly(configPath string) (*app.App, error) {
	cfg, err := config.Load(config.Options{FilePath: configPath, Env: environ()})
	if err != nil {
		return nil, err
	}
	return app.Build(app.Options{Config: cfg, Env: environ()})
}

// environ snapshots the process environment. It is a separate function so
// tests can reason about the resolution inputs without touching os.Environ.
func environ() map[string]string {
	env := os.Environ()
	out := make(map[string]string, len(env))
	for _, kv := range env {
		for i := 0; i < len(kv); i++ {
			if kv[i] == '=' {
				out[kv[:i]] = kv[i+1:]
				break
			}
		}
	}
	return out
}
