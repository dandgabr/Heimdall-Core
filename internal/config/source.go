package config

// This file adds the PROVENANCE layer used by `heimdall config show`: for each
// resolved key it records which precedence layer last set it (default < file <
// flag < env, per ADR-002). It is purely additive: Load keeps its signature and
// simply discards the provenance, so no existing caller changes.

// Source names the layer a resolved value came from.
type Source string

const (
	// SourceDefault means no file/flag/env supplied the key, so the built-in
	// default stands.
	SourceDefault Source = "default"
	// SourceFile means the config file supplied it.
	SourceFile Source = "file"
	// SourceFlag means a command-line flag supplied it.
	SourceFlag Source = "flag"
	// SourceEnv means an environment variable supplied it. Env has the highest
	// precedence, so it wins over every other layer.
	SourceEnv Source = "env"
)

// Fields is the per-key provenance of one resolution: dotted config key ->
// layer that last set it. A key absent from the map was never set and is at its
// default.
type Fields map[string]Source

// SourceOf returns the recorded source for a key, or SourceDefault.
func (f Fields) SourceOf(key string) Source {
	if f == nil {
		return SourceDefault
	}
	if s, ok := f[key]; ok {
		return s
	}
	return SourceDefault
}
