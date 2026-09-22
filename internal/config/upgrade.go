package config

// Upgrade migrates a flattened config from any past schema version to
// CurrentConfigVersion. It is intentionally a no-op at v1 (there is no older
// version yet) but exists now so the first real migration lands in an
// established seam rather than being retrofitted around a hardcoded check.
//
// Contract: the input is the flattened file map; the output is the same map
// promoted to the current version. Unknown keys are preserved.
func Upgrade(in map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	out["config_version"] = itoa(CurrentConfigVersion)
	return out, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
