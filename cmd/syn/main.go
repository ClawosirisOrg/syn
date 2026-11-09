// SPDX-License-Identifier: AGPL-3.0-or-later

// Command syn exposes only offline Phase 1 operations; live commands fail closed.
package main

import (
	"fmt"
	"io"
	"os"
)

var version = "dev"

// Exit codes: 0 success, 2 invalid input, 3 safety stop, 4 unavailable,
// 5 local operation failure, 124 deadline/cancellation.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		fmt.Fprintln(stdout, version)
		return 0
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: syn <version|validate-config|review-fixture|serve|review-github|replay-delivery> (see cmd/syn/README.md)")
		return 2
	}
	switch args[0] {
	case "version":
		if len(args) != 1 {
			fmt.Fprintln(stderr, "version takes no arguments")
			return 2
		}
		fmt.Fprintln(stdout, version)
		return 0
	case "validate-config":
		return validateConfig(args[1:], stdout, stderr)
	case "review-fixture":
		return reviewFixture(args[1:], stdout, stderr)
	case "serve", "review-github", "replay-delivery":
		fmt.Fprintln(stderr, "unavailable: live intake, credentials, provider, replay and publication are disabled")
		return 4
	default:
		fmt.Fprintln(stderr, "unknown command or flag")
		return 2
	}
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
