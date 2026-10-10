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
- Tests never run real tools: the CLI's `newRunner`, `lookPath`, `systemProbe`, `runningApps`, `openFiles` and `installedApps` are replaced in `internal/cli/main_test.go`. The one exception is `plutil` run on a temp file, to build a binary plist fixture.

## Performance
- Profile real scans with the hidden flag: `HOME=<scratch> ./bin/sweep scan / --cpuprofile cpu.prof` (HOME redirect keeps the cache out of the real home), then `go tool pprof -top bin/sweep cpu.prof`.
- `TestFastReadDirMatchesPortable` / `TestScanSameWithEitherReader` must stay green: the getattrlistbulk reader has to agree with readdir+lstat.

## Adding or changing a feature
sweep must stay small and trustworthy. Every change follows these rules; a feature that cannot meet them is not ready.

1. **Fits the goal.** One job: find space and clean it safely. Extend what exists (a rule, a detector, a `show`/`clean` flag) before adding anything new. No new command without the user agreeing first.
2. **One owner per fact.** Every list or table lives in one place, and everything else derives from it. What a synthetic rule's detector does, and how its findings are cleaned, is declared in `internal/rules/detectors.go`. Rule IDs are shared as constants, and no package special-cases a rule ID to change safety behaviour. Running tools lives in `internal/macos` / `internal/apps`, rules in `internal/rules`, deletion only in `internal/cleaner`.
3. **Fails closed.** Anything that selects files for cleaning must treat "unsure" as "keep": unreadable, a tool missing or failing, an ambiguous name. It must also be re-decided right before deletion (the cleaner re-runs `Set.Match`, `Guard.Revalidate`, the open-files check and the content check), and it goes through `safety.Guard` and the `Executor`, never deleting directly. New cleanable categories start at CAUTION or REVIEW, not SAFE.
4. **External tools behind a seam.** Calls to `lsof`, `mdfind`, `codesign`, `plutil`, `lsappinfo`, `tmutil` and similar go through a replaceable function or interface. Parsing is a pure function with unit tests. Tests never run a tool that reads or changes the real system; `internal/cli/main_test.go` replaces them all.
5. **Tests prove the safety.** Cover both "offered" and "must not be offered" cases, including a sandbox end-to-end test. Mutation-check every safety check: disable it, see a test fail, restore it.
6. **Verify before reporting.** Run, in this order:
   - `gofmt -l .` (must print nothing)
   - `go vet ./...`
   - `golangci-lint run` (0 issues)
   - `go test ./...` and `GOARCH=amd64 go test ./...`
   - `go test -race` on packages with concurrency
   - `go run golang.org/x/tools/cmd/deadcode@latest -test ./...` (no output)
   - when it helps, a dry run against real data, never with `--execute`
7. **Docs in the same change.** Update the README (and SPEC for commands), help text and the rule count.
8. **Review your own diff** before calling it done: no special cases bolted on, no duplicated logic, no dead code, and comments that say why.
