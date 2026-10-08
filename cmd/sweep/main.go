// Command sweep is a macOS disk analyzer and safe cleaner.
package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/mishraprayash/macsweep/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...". Builds
// made with 'go install ...@v0.2.0' leave it unset and get the module
// version from the build info instead.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, buildVersion())
	stop()
	os.Exit(code)
}

func buildVersion() string {
	v := version
	if v == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
	}
	return strings.TrimPrefix(v, "v")
}
