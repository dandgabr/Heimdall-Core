package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dandgabr/heimdall-core/internal/app"
	"github.com/dandgabr/heimdall-core/internal/config"
	"github.com/dandgabr/heimdall-core/internal/domain"
	"github.com/dandgabr/heimdall-core/internal/i18n"
)

// This file implements the F5.3 read-only CLI groups: `quota`, `gate` and
// `config`. Every command localises its messages from the embedded catalogs
// (ADR-002): a rendered line is `bundle.Format(lang, code, params)`, never
// server prose. A renderer is PURE (data in, bytes out) so each branch — an
// empty list, a not-enabled gate, a write failure — is reachable in a test
// without an App.

// --- quota ---

// newQuotaCmd groups the quota inspection commands (ADR-0011). Quota is a
// per-credential FILTER state; these commands only READ it.
func newQuotaCmd() *cobra.Command {
	quota := &cobra.Command{
		Use:   "quota",
		Short: "Inspect per-credential quota state",
		Long: "Inspect the per-credential quota windows (ADR-0011).\n\n" +
			"Quota is observed state (from upstream headers, retry hints and local\n" +
			"counters), not operator-editable data. These commands read it; there is\n" +
			"deliberately NO `reset` — clearing recorded state would hide real usage\n" +
			"and risk overspending the plan.",
	}
	quota.AddCommand(newQuotaListCmd(), newQuotaShowCmd())
	return quota
}

func newQuotaListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List quota windows and remaining fraction per credential",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			infos, err := instance.QuotaInfos()
			if err != nil {
				return err
			}
			return renderQuotaList(cmd.OutOrStdout(), infos, instance.Bundle)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

func newQuotaShowCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "show <credential-id>",
		Short: "Show the quota detail for one credential",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			info, found, err := instance.QuotaInfoFor(args[0])
			if err != nil {
				return err
			}
			if !found {
				return domain.New(domain.CodeCLIQuotaUnknown,
					domain.WithHTTPStatus(404),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{"id": args[0]}),
				)
			}
			return renderQuotaDetail(cmd.OutOrStdout(), info, instance.Bundle)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// renderQuotaList writes one line per credential, then one line per window. An
// empty vault prints nothing (a valid, honest state).
func renderQuotaList(out io.Writer, infos []app.QuotaInfo, bundle *i18n.Bundle) error {
	lang := cliLanguage(bundle)
	for _, info := range infos {
		if !info.HasState {
			if _, err := fmt.Fprintf(out, "%s\tprovider=%s\t%s\n",
				info.Credential, info.Provider,
				bundle.Format(lang, domain.CodeCLIQuotaNoState, map[string]string{"id": info.Credential})); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(out, "%s\tprovider=%s\tterminal=%s\n",
			info.Credential, info.Provider, terminalLabel(info.TerminalCode)); err != nil {
			return err
		}
		for _, w := range info.Windows {
			if _, err := fmt.Fprintf(out, "  %s\n", quotaWindowLine(w)); err != nil {
				return err
			}
		}
	}
	return nil
}

// renderQuotaDetail writes one credential's windows in a labelled block.
func renderQuotaDetail(out io.Writer, info app.QuotaInfo, bundle *i18n.Bundle) error {
	lang := cliLanguage(bundle)
	if _, err := fmt.Fprintf(out, "credential\t%s\nprovider\t%s\n",
		info.Credential, info.Provider); err != nil {
		return err
	}
	if info.TerminalCode != "" {
		if _, err := fmt.Fprintf(out, "terminal\t%s\n", info.TerminalCode); err != nil {
			return err
		}
	}
	if !info.HasState {
		_, err := fmt.Fprintln(out, bundle.Format(lang, domain.CodeCLIQuotaNoState,
			map[string]string{"id": info.Credential}))
		return err
	}
	for _, w := range info.Windows {
		if _, err := fmt.Fprintln(out, quotaWindowLine(w)); err != nil {
			return err
		}
	}
	return nil
}

// quotaWindowLine renders one window deterministically: kind, used/limit,
// remaining percent, reset and source. It never prints a secret (there is none).
func quotaWindowLine(w app.QuotaWindowInfo) string {
	remaining := "n/a"
	if w.Limit > 0 {
		remaining = fmt.Sprintf("%.1f%%", w.Remaining*100)
	}
	reset := w.ResetsAt
	if reset == "" {
		reset = "-"
	}
	return fmt.Sprintf("kind=%s used=%.0f limit=%.0f remaining=%s resets_at=%s source=%s",
		w.Kind, w.Used, w.Limit, remaining, reset, w.Source)
}

// terminalLabel renders an empty terminal code as "-" so the column is stable.
func terminalLabel(code string) string {
	if code == "" {
		return "-"
	}
	return code
}

// --- gate ---

// newGateCmd groups the gate inspection commands (ADR-0014). The chain is built
// ONCE at boot from the config, so there is no runtime enable/disable; the group
// documents that explicitly.
func newGateCmd() *cobra.Command {
	gate := &cobra.Command{
		Use:   "gate",
		Short: "Inspect the effective gate chain (DAG order, stages, policies)",
		Long: "Inspect the effective gate chain and its dependency-derived order\n" +
			"(ADR-0014).\n\n" +
			"Gates are enabled in the configuration file\n" +
			"(features.gates.<id>, and the token/memory/security group switches); the\n" +
			"chain and its order are computed once at boot, so there is no runtime\n" +
			"enable/disable. Disabling a gate is a config change followed by a restart.",
	}
	gate.AddCommand(newGateListCmd(), newGateShowCmd())
	return gate
}

func newGateListCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the effective gates in DAG execution order",
		RunE: func(cmd *cobra.Command, _ []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			return renderGateList(cmd.OutOrStdout(), instance.GateInfos(), instance.Bundle)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

func newGateShowCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "show <name>",
		Short: "Show one gate's stages, failure policy, caps and dependencies",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			instance, err := buildReadOnly(configPath)
			if err != nil {
				return err
			}
			defer func() { _ = instance.Close() }()

			info, found := instance.GateInfoByName(args[0])
			if !found {
				return domain.New(domain.CodeCLIGateNotEnabled,
					domain.WithHTTPStatus(404),
					domain.WithScope(domain.ScopeRequest),
					domain.WithParams(map[string]string{"name": args[0]}),
				)
			}
			return renderGateDetail(cmd.OutOrStdout(), info, instance.Bundle)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// renderGateList writes the gates grouped by stage, preserving the DAG order.
func renderGateList(out io.Writer, infos []app.GateInfo, bundle *i18n.Bundle) error {
	lang := cliLanguage(bundle)
	_ = lang // the list is metadata; no code needs localising beyond headings
	for _, g := range infos {
		if _, err := fmt.Fprintf(out, "%s\tstages=%s\tpolicy=%s\tgroup=%s\n",
			g.ID, strings.Join(g.Stages, ","), g.FailurePolicy, g.Group); err != nil {
			return err
		}
	}
	return nil
}

// renderGateDetail writes one gate's full metadata, including its declared
// read/write set and explicit dependencies.
func renderGateDetail(out io.Writer, g app.GateInfo, bundle *i18n.Bundle) error {
	lang := cliLanguage(bundle)
	_ = lang
	if _, err := fmt.Fprintf(out, "id\t%s\nstages\t%s\npolicy\t%s\ngroup\t%s\nrequired_caps\t%s\n",
		g.ID, strings.Join(g.Stages, ","), g.FailurePolicy, g.Group, g.RequiredCaps); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(out, "reads\t%s\nwrites\t%s\nafter\t%s\n",
		joinOrDash(g.Reads), joinOrDash(g.Writes), joinOrDash(g.After)); err != nil {
		return err
	}
	// Document the config-only switching for every gate, so the missing
	// enable/disable command is never a surprise.
	_, err := fmt.Fprintln(out, bundle.Format(lang, domain.CodeCLIGateConfigOnly, nil))
	return err
}

// joinOrDash renders a slice joined by commas, or "-" when empty.
func joinOrDash(items []string) string {
	if len(items) == 0 {
		return "-"
	}
	return strings.Join(items, ",")
}

// --- config ---

// newConfigCmd groups the configuration inspection commands. None of them
// prints a secret: `show` renders the redacted projection owned by the config
// package (config.RedactedFields), `validate` reports by code, and `path`
// prints only the file location.
func newConfigCmd() *cobra.Command {
	cfg := &cobra.Command{
		Use:   "config",
		Short: "Inspect and validate the effective configuration",
	}
	cfg.AddCommand(newConfigShowCmd(), newConfigValidateCmd(), newConfigPathCmd())
	return cfg
}

// configOptions builds the config.Options for a read-only config command. Only
// the explicit --config flag and the environment participate; flags like
// host/port do not apply to `config` commands.
func configOptions(configPath string) config.Options {
	return config.Options{FilePath: configPath, Env: environ()}
}

func newConfigShowCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the effective configuration (secrets redacted) and each field's origin",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, sources, err := config.LoadWithSources(configOptions(configPath))
			if err != nil {
				return err
			}
			hasFile := config.ResolvePath(configOptions(configPath)) != ""
			return renderConfigShow(cmd.OutOrStdout(), cfg, sources, hasFile)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// renderConfigShow writes the redacted effective config. Each line is
// `key value source`, where source is default|file|flag|env (ADR-002
// precedence). The VALUES come from config.RedactedFields, so a secret-bearing
// key is already substituted before the CLI sees it.
func renderConfigShow(out io.Writer, cfg config.Config, sources config.Fields, hasFile bool) error {
	bundle := i18n.MustNew()
	lang := cliLanguage(bundle)
	// Warn when no file was found, so defaults-only operation is explicit.
	if !hasFile {
		if _, err := fmt.Fprintln(out, bundle.Format(lang, domain.CodeCLIConfigNoFile, nil)); err != nil {
			return err
		}
	}
	for _, f := range config.RedactedFields(cfg, sources) {
		if _, err := fmt.Fprintf(out, "%s\t%s\t%s\n", f.Key, f.Value, f.Source); err != nil {
			return err
		}
	}
	return nil
}

func newConfigValidateCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Load and validate the configuration, reporting errors by code",
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(configOptions(configPath))
			if err != nil {
				return err
			}
			return renderConfigValidate(cmd.OutOrStdout(), cfg)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}

// renderConfigValidate prints an "ok" line on success. Renderer is separate so
// the write-failure branch is testable.
func renderConfigValidate(out io.Writer, cfg config.Config) error {
	_, err := fmt.Fprintf(out, "ok\tconfig_version=%d\n", cfg.ConfigVersion)
	return err
}

func newConfigPathCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Print the configuration file in effect",
		RunE: func(cmd *cobra.Command, _ []string) error {
			path := config.ResolvePath(configOptions(configPath))
			if path == "" {
				// No file: report the documented no-file code so the operator
				// knows defaults are in effect (and the exit is non-zero so a
				// script can detect it).
				return domain.New(domain.CodeCLIConfigNoFile,
					domain.WithHTTPStatus(404),
					domain.WithScope(domain.ScopeRequest))
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), path)
			return err
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to the TOML configuration file")
	return cmd
}
