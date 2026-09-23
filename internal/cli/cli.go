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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dandgabr/heimdall-core/internal/app"
	"github.com/dandgabr/heimdall-core/internal/combos"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/contracts"
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
	root.AddCommand(newServeCmd(), newVersionCmd(), newTokenCmd(), newClientKeyCmd(), newProviderCmd(), newLoginCmd(), newComboCmd(), newQuotaCmd(), newGateCmd(), newConfigCmd())
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
				Config:  cfg,
				Env:     environ(),
				Version: Version,
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

			instance, err := app.Build(app.Options{Config: cfg, Env: environ(), Version: Version})
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

// newClientKeyCmd groups the downstream client-key commands (F5.1,
// ADR-SEC-06 §2). A client key authenticates the inference gateway (/v1/*) and
// is a different credential class from the management token. `create` prints
// the plaintext key exactly once (like `token rotate` writes its file); the
// value is never logged and never printed again.
func newClientKeyCmd() *cobra.Command {
	key := &cobra.Command{
		Use:   "client-key",
		Short: "Manage downstream client keys for the inference gateway (/v1/*)",
	}
	key.AddCommand(newClientKeyCreateCmd(), newClientKeyListCmd(), newClientKeyRevokeCmd())
	return key
}

func newClientKeyCreateCmd() *cobra.Command {
	var (
		configPath string
		label      string
	)
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Issue a new client key (printed once, stored only as a hash)",
		Long: "Issue a new client key for the inference gateway (/v1/*).\n\n" +
			"The plaintext key is printed ONCE and never persisted: the vault keeps\n" +
			"only its SHA-256 hash, exactly like the management token. Store it now;\n" +
			"it cannot be recovered.\n\n" +
			"    heimdall client-key create --label editor",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			rec, plaintext, err := instance.CreateClientKey(cmd.Context(), label)
			if err != nil {
				return err
			}
			// Line 1: the non-secret metadata (id, label). Line 2: the KEY,
			// and only the key, so a script can capture it without parsing. It
			// never goes through the catalog or the logger.
			if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\tlabel=%s\n",
				rec.ID, rec.Label); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), plaintext)
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	cmd.Flags().StringVar(&label, "label", "", "human label for the key")
	return cmd
}

func newClientKeyListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List client keys (id/label/state only; never the key)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			list, err := instance.ListClientKeys(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, k := range list {
				state := "active"
				if !k.RevokedAt.IsZero() {
					state = "revoked"
				}
				if _, err := fmt.Fprintf(out, "%s\tlabel=%s\t%s\n",
					k.ID, k.Label, state); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

func newClientKeyRevokeCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a client key by id (the key stops authenticating immediately)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			if err := instance.RevokeClientKey(cmd.Context(), domain.ClientID(args[0])); err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), args[0])
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// newLoginCmd implements `heimdall login <provider-id>` (BD-02): the
// interactive OAuth login for OAuth providers (Antigravity) and the typed
// refusal pointing at `provider add-key` for API-key providers. The
// authorization URL is printed for the browser; the grant completes either on
// the ephemeral loopback callback or, with --code, from a pasted authorization
// code (a browser that cannot reach 127.0.0.1). `--status` reports the stored
// login without ever opening the sealed credential.
//
// No token ever reaches the output: the persisted credential is sealed in the
// vault and the printed result line carries identity metadata only.
func newLoginCmd() *cobra.Command {
	var (
		configPath string
		code       string
		status     bool
	)
	cmd := &cobra.Command{
		Use:   "login <provider-id>",
		Short: "Authenticate a provider (OAuth login; API-key providers use `provider add-key`)",
		Long: "Run the interactive OAuth login for an OAuth provider:\n\n" +
			"    heimdall login antigravity\n\n" +
			"The authorization URL is printed; opening it completes the grant on a\n" +
			"local loopback callback. When the browser cannot reach 127.0.0.1\n" +
			"(headless/remote session), paste the code from the redirect URL:\n\n" +
			"    heimdall login antigravity --code <authorization-code>\n\n" +
			"The client secret, when the provider requires one, comes from the\n" +
			"provider's config (client_secret / client_secret_env) — it is never\n" +
			"prompted, printed or logged. The stored tokens are sealed in the vault.\n" +
			"Inspect the stored login with `heimdall login --status <provider-id>`.\n" +
			"API-key providers do not log in: use `heimdall provider add-key`.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			id := domain.ProviderID(args[0])
			if status {
				st, err := instance.LoginStatus(cmd.Context(), id)
				if err != nil {
					return err
				}
				return renderLoginStatus(cmd.OutOrStdout(), st)
			}

			session, err := instance.BeginLogin(cmd.Context(), id)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			lang := cliLanguage(instance.Bundle)
			// The ToS risk notice (ADR-0003 §4) precedes everything: login is
			// the moment the subscription session is connected.
			if notice := session.RiskNotice(); notice != "" {
				if _, err := fmt.Fprintf(out, "  ! %s\n", instance.Bundle.Format(lang, notice, nil)); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintln(out, instance.Bundle.Format(lang, domain.CodeCLILoginOpenURL,
				map[string]string{"provider": string(id), "url": session.AuthURL()})); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(out, instance.Bundle.Format(lang, domain.CodeCLILoginCodeHint, nil)); err != nil {
				return err
			}
			res, err := session.Complete(cmd.Context(), code)
			if err != nil {
				return err
			}
			// Identity metadata only — never a token.
			_, err = fmt.Fprintf(out, "%s\tprovider=%s\tlabel=%s\temail=%s\tproject=%s\tplan=%s\n",
				res.CredentialID, res.Provider, res.Label, res.Email, res.Project, res.Plan)
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	cmd.Flags().StringVar(&code, "code", "", "paste the authorization code instead of waiting for the local callback")
	cmd.Flags().BoolVar(&status, "status", false, "show the stored login state (no secrets)")
	return cmd
}

// renderLoginStatus prints `login --status` as key=value data lines: the
// logged-in view carries identity metadata and the access-token expiry, the
// logged-out view the readiness reason code. No secret field exists here.
func renderLoginStatus(out io.Writer, st app.LoginStatus) error {
	if !st.LoggedIn {
		reason := st.ReasonCode
		if reason == "" {
			reason = "logged-out"
		}
		_, err := fmt.Fprintf(out, "%s\tstate=logged-out\treason=%s\n", st.Provider, reason)
		return err
	}
	expires, state := "unknown", "valid"
	if !st.ExpiresAt.IsZero() {
		expires = st.ExpiresAt.UTC().Format(time.RFC3339)
		if st.Expired {
			state = "expired"
		}
	}
	_, err := fmt.Fprintf(out, "%s\tcredential=%s\tlabel=%s\temail=%s\tproject=%s\tplan=%s\texpires=%s\tstate=%s\n",
		st.Provider, st.CredentialID, st.Label, st.Email, st.Project, st.Plan, expires, state)
	return err
}

// newProviderCmd groups the read/management provider commands. None of them// performs network I/O: `list` and `status` only inspect the registry and the
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

// newComboCmd groups the combo management commands. A combo is a named,
// validated DAG of routing steps (ADR-0013): create validates and persists,
// list reads the durable set, delete removes one.
func newComboCmd() *cobra.Command {
	combo := &cobra.Command{
		Use:   "combo",
		Short: "Create, list and delete named routing combos",
	}
	combo.AddCommand(newComboListCmd(), newComboCreateCmd(), newComboDeleteCmd())
	return combo
}

// parseComboSteps parses a compact step list. Each step is
// `kind:ref[:weight]`:
//
//	model:glm-4.6
//	provider:z.ai
//	combo:base
//	model:glm-4.6:5      (weight 5 for `weighted`)
//
// The kind is one of model|provider|combo. This is deliberately a small,
// scriptable grammar; the GUI/TOML combo authoring is a later phase.
func parseComboSteps(raw []string) ([]combos.Step, error) {
	steps := make([]combos.Step, 0, len(raw))
	for _, item := range raw {
		parts := strings.Split(item, ":")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, domain.New(domain.CodeRouteInvalidCombo,
				domain.WithHTTPStatus(400),
				domain.WithScope(domain.ScopeRequest),
				domain.WithParams(map[string]string{"name": item, "reason": "step must be kind:ref[:weight]"}),
			)
		}
		step := combos.Step{Ref: parts[1]}
		switch parts[0] {
		case "model":
			step.Kind = combos.StepModel
		case "provider":
			step.Kind = combos.StepProviderWildcard
		case "combo":
			step.Kind = combos.StepComboRef
		default:
			return nil, domain.New(domain.CodeRouteInvalidCombo,
				domain.WithHTTPStatus(400),
				domain.WithScope(domain.ScopeRequest),
				domain.WithParams(map[string]string{"name": item, "reason": "unknown step kind " + parts[0]}),
			)
		}
		if len(parts) >= 3 && parts[2] != "" {
			w, err := strconv.Atoi(parts[2])
			if err != nil {
				return nil, domain.New(domain.CodeRouteInvalidCombo,
					domain.WithHTTPStatus(400),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{"name": item, "reason": "weight is not an integer"}),
				)
			}
			step.Weight = w
		}
		steps = append(steps, step)
	}
	return steps, nil
}

func newComboCreateCmd() *cobra.Command {
	var (
		configPath string
		strategy   string
	)
	cmd := &cobra.Command{
		Use:   "create <name> <step>...",
		Short: "Create (or replace) a named combo; each step is kind:ref[:weight]",
		Long: "Create a named combo.\n\n" +
			"Each step has the form `kind:ref[:weight]`, where kind is one of\n" +
			"model|provider|combo:\n\n" +
			"    heimdall combo create fast model:glm-4.6 provider:z.ai --strategy fallback",
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			steps, err := parseComboSteps(args[1:])
			if err != nil {
				return err
			}
			sk, ok := contracts.ParseStrategyKind(strategy)
			if !ok {
				return domain.New(domain.CodeRouteInvalidCombo,
					domain.WithHTTPStatus(400),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{"name": args[0], "reason": "unknown strategy " + strategy}),
				)
			}
			combo := combos.NewCombo(args[0], sk, steps)
			if _, getErr := instance.Combos.Get(cmd.Context(), combo.ID); getErr == nil {
				if err := instance.Combos.Update(cmd.Context(), combo); err != nil {
					return err
				}
			} else if err := instance.Combos.Create(cmd.Context(), combo); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\tstrategy=%s\tsteps=%d\n", combo.Name, combo.Strategy, len(combo.Steps))
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	cmd.Flags().StringVar(&strategy, "strategy", string(contracts.StrategyFallback), "routing strategy")
	return cmd
}

func newComboListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the persisted combos",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			list, err := instance.Combos.List(cmd.Context())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			for _, c := range list {
				if _, err := fmt.Fprintf(out, "%s\tstrategy=%s\tdepth=%d\tsteps=%d\n",
					c.Name, c.Strategy, c.Depth, len(c.Steps)); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

func newComboDeleteCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete a persisted combo",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			if err := instance.Combos.Delete(cmd.Context(), domain.ComboID(args[0])); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "deleted\t%s\n", args[0])
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// buildReadOnly is the seam the read-only management commands use to build the
// app without starting the listener. It is a package variable so a test can
// inject an App whose vault has since become unreadable, reaching the commands'
// store-error branches (which a fresh boot fails closed before).
var buildReadOnly = func(configPath string) (*app.App, error) {
	cfg, err := config.Load(config.Options{FilePath: configPath, Env: environ()})
	if err != nil {
		return nil, err
	}
	return app.Build(app.Options{Config: cfg, Env: environ(), Version: Version})
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
