package contracts

// This file adds the OPTIONAL, ADDITIVE body-consumer declaration of ADR-SEC-03
// §2: a gate that NEEDS the request body must declare it, and only then does the
// caller deliver GateInput.Body. It does NOT change the frozen Gate interface —
// a gate that does not implement it never receives a body.

// BodyConsumer is implemented by a gate that requires the canonical request body
// to do its job (e.g. the token gate, which compresses the prompt). It is the
// SEC-03 "declare the need" capability, expressed as an optional interface so
// the frozen Gate contract and every existing gate stay unchanged.
//
// The caller (the HTTP boundary / gateway) delivers Body ONLY when at least one
// gate acting in the stage is a BodyConsumer; otherwise Body stays nil, so a
// gate that did not ask cannot read a payload by accident.
type BodyConsumer interface {
	// NeedsBody reports that the gate requires GateInput.Body (and, when it
	// acts per chunk, ChunkInput.Body). A gate that returns false must not read
	// Body even if a caller populated it.
	NeedsBody() bool
}

// ConsumesBody reports whether g needs the request body delivered. A nil gate,
// or one that does not implement BodyConsumer, returns false, so the safe
// default is "no body".
func ConsumesBody(g Gate) bool {
	if g == nil {
		return false
	}
	bc, ok := g.(BodyConsumer)
	return ok && bc.NeedsBody()
}

// AnyConsumesBody reports whether any gate in the slice needs the body. The
// caller uses it once per stage at boot to decide whether to populate Body.
func AnyConsumesBody(gates []Gate) bool {
	for _, g := range gates {
		if ConsumesBody(g) {
			return true
		}
	}
	return false
}
