// Package cli implements the Heimdall command-line interface.
//
// Commands are thin: they resolve configuration, build the app and translate
// errors to a localised message plus a non-zero exit code. No business logic
// lives here.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

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

// ExecuteWith is Execute with injectable output streams, so the binary's run()
// wrapper and tests can drive the real CLI without touching the process streams.
func ExecuteWith(args []string, stdout, stderr io.Writer) int {
	return executeWith(stderr, stdout, args)
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

// newBundle is a seam over i18n.New so a test can force a catalog failure and
// reach executeWith's bootstrap-error branch. Production uses i18n.New.
var newBundle = i18n.New

func executeWith(stderr, stdout io.Writer, args []string) int {
	bundle, err := newBundle()
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

// serveRun is the seam the serve command uses to block on the listener. It is a
// package variable so a test can drive the command without binding a socket.
var serveRun = func(ctx context.Context, instance *app.App) error {
	return instance.Run(ctx)
}

// changedServeFlags returns only the flags the user actually set, keyed by flag
// name, so config.Load's precedence sees flags only when they were supplied.
func changedServeFlags(cmd *cobra.Command) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"host", "port", "allow-remote"} {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			out[name] = f.Value.String()
		}
	}
	return out
}

func newServeCmd() *cobra.Command {
	flags := &serveFlags{}
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Heimdall gateway and management API",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(config.Options{
				FilePath: flags.configPath,
				Flags:    changedServeFlags(cmd),
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
			return serveRun(ctx, instance)
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
	provider.AddCommand(newProviderListCmd(), newProviderStatusCmd(), newProviderImportCmd(), newProviderTestCmd(), newProviderAddKeyCmd())
	return provider
}

// cliStdin is the input source for `provider add-key`. It is a package variable
// so a test can drive the command without touching the process stdin; production
// uses os.Stdin.
var cliStdin io.Reader = os.Stdin

// terminalFd returns the fd of a reader that is an interactive terminal, and
// whether it is one. It is a seam so a test can exercise the no-echo branch
// without a real TTY.
var terminalFd = func(r io.Reader) (uintptr, bool) {
	f, ok := r.(*os.File)
	if !ok {
		return 0, false
	}
	fd := f.Fd()
	return fd, term.IsTerminal(int(fd))
}

// readPasswordNoEcho reads a line from a terminal fd without echo. It is a seam
// over term.ReadPassword.
var readPasswordNoEcho = func(fd uintptr) ([]byte, error) {
	return term.ReadPassword(int(fd))
}

// readSecretNoEcho reads an API key WITHOUT echoing it. On a terminal it uses
// term.ReadPassword (no echo); otherwise it reads from the non-terminal reader
// (a pipe/file, where echo does not apply). A single trailing newline is
// trimmed; interior whitespace is preserved (the shape check rejects it later).
func readSecretNoEcho(in io.Reader, prompt io.Writer) (string, error) {
	if fd, ok := terminalFd(in); ok {
		if prompt != nil {
			_, _ = fmt.Fprint(prompt, "API key: ")
		}
		raw, err := readPasswordNoEcho(fd)
		if prompt != nil {
			_, _ = fmt.Fprintln(prompt)
		}
		if err != nil {
			return "", domain.New(domain.CodeProviderAPIKeyReadFailed,
				domain.WithHTTPStatus(500),
				domain.WithCause(err),
				domain.WithParams(map[string]string{"reason": "could not read the key from the terminal"}),
			)
		}
		return strings.TrimRight(string(raw), "\r\n"), nil
	}
	raw, err := io.ReadAll(in)
	if err != nil {
		return "", domain.New(domain.CodeProviderAPIKeyReadFailed,
			domain.WithHTTPStatus(500),
			domain.WithCause(err),
			domain.WithParams(map[string]string{"reason": "could not read the key from stdin"}),
		)
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

func newProviderAddKeyCmd() *cobra.Command {
	var (
		configPath string
		label      string
	)
	cmd := &cobra.Command{
		Use:   "add-key <provider-id>",
		Short: "Add an API key for a provider (read from stdin, sealed into the vault)",
		Long: "Add an API key for an API-key provider.\n\n" +
			"The key is read from STDIN and NEVER from a command-line argument (which\n" +
			"would leak into the shell history and `ps`). On a terminal the prompt does\n" +
			"not echo; piped input is read directly:\n\n" +
			"    printf '%s' \"$KEY\" | heimdall provider add-key z.ai --label work",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			key, err := readSecretNoEcho(cliStdin, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			id := domain.ProviderID(args[0])
			res, err := instance.AddAPIKey(cmd.Context(), id, label, key)
			if err != nil {
				return err
			}
			// Report the id, label and provider only; NEVER the key.
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\tprovider=%s\tlabel=%s\n",
				res.CredentialID, res.Provider, res.Label)
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	cmd.Flags().StringVar(&label, "label", "", "human label for the credential (defaults to the provider id)")
	return cmd
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

			return writeProviderList(cmd.OutOrStdout(), instance, cmd.Context())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// writeProviderList renders `provider list`, including the per-provider ToS risk
// notice (ADR-0003 §4) when the descriptor declares one.
func writeProviderList(out io.Writer, instance *app.App, ctx context.Context) error {
	return renderProviderList(out, instance.ProviderList(ctx), instance.Bundle)
}

// renderProviderList is the pure renderer behind writeProviderList. It takes the
// data directly so every branch (pending, not-ready, risk notice, write failure)
// is reachable in a test without constructing an App.
//
// The `state` column is HONEST: "ready" only when the vault holds a usable
// credential (summary.Ready). A pending provider shows its pending fields; any
// other not-ready provider shows its i18n reason code, matching `provider status`.
func renderProviderList(out io.Writer, list []app.ProviderSummary, bundle *i18n.Bundle) error {
	lang := cliLanguage(bundle)
	for _, p := range list {
		modes := strings.Join(p.AuthModes, ",")
		state := providerState(p.Ready, p.Future, p.ReasonCode, p.PendingEndpoints)
		if _, err := fmt.Fprintf(out, "%s\tprotocol=%s\tauth=%s\t%s\n",
			p.ID, p.Protocol, modes, state); err != nil {
			return err
		}
		// A future provider shows its distinct state plus the localised
		// provider.future message (a planned expansion, not a user-fixable block).
		if p.Future {
			if _, err := fmt.Fprintf(out, "  > %s\n", bundle.Format(lang, domain.CodeProviderFuture, map[string]string{"provider": string(p.ID)})); err != nil {
				return err
			}
		}
		if p.RiskNotice != "" {
			if _, err := fmt.Fprintf(out, "  ! %s\n", bundle.Format(lang, p.RiskNotice, nil)); err != nil {
				return err
			}
		}
	}
	return nil
}

// providerState renders the shared state label for a provider row. Both
// `provider list` and `provider status` use it, so the two views cannot drift.
//
// A future provider shows the dedicated "future" label rather than
// "blocked(provider.future)": it is a planned expansion, not a user-fixable
// condition.
func providerState(ready, future bool, reasonCode string, pending []string) string {
	if future {
		return "future"
	}
	if len(pending) > 0 {
		return "pending: " + strings.Join(pending, ",")
	}
	if ready {
		return "ready"
	}
	if reasonCode != "" {
		return "blocked(" + reasonCode + ")"
	}
	return "blocked"
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

			return writeProviderStatus(cmd.OutOrStdout(), instance, cmd.Context())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// writeProviderStatus renders `provider status`, including the risk notice.
func writeProviderStatus(out io.Writer, instance *app.App, ctx context.Context) error {
	return renderProviderStatus(out, instance.ProviderStatus(ctx), instance.Bundle)
}

// renderProviderStatus is the pure renderer behind writeProviderStatus.
func renderProviderStatus(out io.Writer, list []app.ProviderStatus, bundle *i18n.Bundle) error {
	lang := cliLanguage(bundle)
	for _, s := range list {
		state := providerState(s.Ready, s.Future, s.ReasonCode, nil)
		if _, err := fmt.Fprintf(out, "%s\t%s\n", s.ID, state); err != nil {
			return err
		}
		if s.Future {
			if _, err := fmt.Fprintf(out, "  > %s\n", bundle.Format(lang, domain.CodeProviderFuture, map[string]string{"provider": string(s.ID)})); err != nil {
				return err
			}
		}
		if s.RiskNotice != "" {
			if _, err := fmt.Fprintf(out, "  ! %s\n", bundle.Format(lang, s.RiskNotice, nil)); err != nil {
				return err
			}
		}
	}
	return nil
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

func newProviderTestCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "test <provider-id>",
		Short: "Probe an API-key provider end to end (builds the executor, calls GET /models)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			id := domain.ProviderID(args[0])
			res, err := instance.ProviderTest(cmd.Context(), id)
			if err != nil {
				return err
			}
			// Report the provider, the credential id and the status only; never
			// the key.
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\tcredential=%s\tstatus=%d\n",
				res.Provider, res.CredentialID, res.Status)
			return err
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
