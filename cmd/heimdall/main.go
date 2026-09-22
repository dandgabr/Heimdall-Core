// Command heimdall is the Heimdall Core entry point.
package main

import (
	"io"
	"os"

	"github.com/dandgabr/heimdall-core/internal/cli"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: it is main's whole body minus the os.Exit,
// with the output streams injectable so a test can drive the real CLI and assert
// the exit code and output without spawning a process.
func run(args []string, stdout, stderr io.Writer) int {
	return cli.ExecuteWith(args, stdout, stderr)
}
