// Command heimdall is the Heimdall Core entry point.
package main

import (
	"os"

	"github.com/dandgabr/heimdall-core/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
