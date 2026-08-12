// Command fig is the Falcon Integration Gateway daemon entry point. It hands a
// root context to the cobra command tree (which installs signal-cancellable
// shutdown) and translates a command error into a non-zero exit code.
package main

import (
	"context"
	"log"

	"github.com/crowdstrike/falcon-integration-gateway/internal/cli"
)

func main() {
	if err := cli.Execute(context.Background()); err != nil {
		log.Fatal(err)
	}
}
