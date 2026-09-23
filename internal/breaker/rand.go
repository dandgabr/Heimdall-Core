package breaker

import (
	"math/rand/v2"
)

// randFloat64 is the entropy seam for DefaultJitter. It is a package variable so
// a test can pin the jitter deterministically and exercise both ends of the
// [0.5,1.0) spread; production uses the global math/rand/v2 source, which is
// sufficient because jitter only desynchronises retries and is not a security
// decision.
var randFloat64 = rand.Float64
