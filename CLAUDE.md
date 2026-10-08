This project is specified in SPEC.md. Read it before making changes.
- Never run `sweep clean` with --execute on the real filesystem.
- Tests must use temp directories only.
- Build one phase at a time and stop for review.

## Testing
- Every test that touches the filesystem uses `testutil.NewSandbox(t)` (temp dir, `$HOME` redirected into it). Build fixtures with `testutil.Build`; never reference real home paths.
- Use `testutil.Snapshot`/`AssertUnchanged` to prove read-only operations changed nothing.
- Packages that must only read (scanner, rules, classifier, report) get a `testutil.AssertReadOnlyPackage(t, ".")` test.
- Demos run via `make demo` (fixture tree in a temp sandbox, HOME redirected), never against real folders.
- Go: `go.mod` targets 1.23; `/usr/local/go/bin/go` is the 1.23 toolchain (Homebrew's newer `go` is first on PATH).
- Tests never run real tools: the CLI's `newRunner`, `lookPath`, `systemProbe` and `runningApps` are replaced in `internal/cli/main_test.go`.

## Performance
- Profile real scans with the hidden flag: `HOME=<scratch> ./bin/sweep scan / --cpuprofile cpu.prof` (HOME redirect keeps the cache out of the real home), then `go tool pprof -top bin/sweep cpu.prof`.
- `TestFastReadDirMatchesPortable` / `TestScanSameWithEitherReader` must stay green: the getattrlistbulk reader has to agree with readdir+lstat.
