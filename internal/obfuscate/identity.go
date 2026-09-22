package obfuscate

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/dandgabr/heimdall-core/internal/contracts"
)

// This file holds the fingerprint IDENTITY values: the User-Agent string and the
// synthetic project id. Both are pure and deterministic.
//
// Determinism notes:
//   - UserAgent returns the descriptor's declared UA. It does not fabricate a
//     host platform: ADR-0003 documents that the reference connector pins a
//     darwin/arm64 UA even on Linux, so the UA is a per-provider VALUE in the
//     descriptor, not something this package computes from the host.
//   - SyntheticProject derives from a seed by SHA-256, never crypto/rand
//     directly: the value is stable for a seed, and the caller owns the seed, so
//     a test can assert an exact value and the executor can derive it from a
//     stable per-installation input.

// UserAgent returns the User-Agent to present for desc. An empty obfuscation UA
// returns the empty string, which the executor reads as "send your own". This
// function never invents a UA: for a provider that requires one, the descriptor
// declares it.
func UserAgent(desc contracts.ProviderDescriptor) string {
	return desc.Obfuscation.UserAgent
}

// syntheticProjectWords are the adjective and noun pools the derived project id
// draws from. They are fixed so the derivation is reproducible; the pools mirror
// the shape of the reference connector's generator ("useful-fuze-<hex>") without
// copying a random draw.
var (
	syntheticProjectAdjectives = [...]string{"useful", "bright", "swift", "calm", "bold"}
	syntheticProjectNouns      = [...]string{"fuze", "wave", "spark", "flow", "core"}
)

// SyntheticProject derives a deterministic project id of the form
// "<adjective>-<noun>-<hex>". The adjective/noun are selected by distinct bytes
// of the SHA-256 of the seed, and the suffix is five hex characters of the same
// digest. The same seed always yields the same id; two different seeds differ
// with overwhelming probability.
//
// An empty seed still yields a stable value (the hash of empty input); the
// caller decides whether "no seed" is allowed. This function does not fall back
// to randomness under any input, which is the property that keeps it testable.
func SyntheticProject(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	adj := syntheticProjectAdjectives[int(sum[0])%len(syntheticProjectAdjectives)]
	noun := syntheticProjectNouns[int(sum[1])%len(syntheticProjectNouns)]
	suffix := hex.EncodeToString(sum[2:5])[:5]
	return adj + "-" + noun + "-" + suffix
}
