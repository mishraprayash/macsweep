# Build Spec: `sweep`, a macOS Disk Analyzer & Safe Cleaner (Go CLI)

> **Instructions for Claude Code:** Read this whole document before writing any code. Then propose a plan, confirm the module path and dependency list with me, and build **one phase at a time** (see "Build Phases"). Stop after each phase so I can review. **Never run `clean` against my real filesystem.** All tests and demos must use temporary directories.

---

## 1. Problem & Goal

My Mac's "System Data" category takes 60–70% of my disk. Much of it is regenerable junk: caches, logs, build outputs, dependency folders (`node_modules`, `.next`, etc.), simulator data, Docker images, local Time Machine snapshots, and so on.

I want a single Go CLI that:

1. **Scans** the whole disk (or a given path) quickly and accurately.
2. **Explains** where the space is going, grouped into human-meaningful categories (including what macOS hides inside "System Data").
3. **Classifies** every finding by safety: what is safe to delete, what needs review, and what must never be touched.
4. **Cleans** only what I approve, with dry-run by default, Trash-first deletion, and a full audit log.

Safety beats completeness. A false "safe to delete" is a critical bug; a missed cleanup opportunity is a minor one.

---

## 2. Tech Stack & Conventions

- Go 1.22+ (use the latest stable available). Single static binary, `darwin/arm64` and `darwin/amd64`.
- CLI framework: `spf13/cobra`. Config: YAML via `gopkg.in/yaml.v3`.
- Output: plain tables (`text/tabwriter` or `olekukonko/tablewriter`), colors via `fatih/color` (auto-disable when not a TTY / `NO_COLOR` set), `--json` for machine output.
- Progress: a lightweight spinner/progress line on stderr only (keep stdout clean for piping).
- Optional later: interactive TUI with `charmbracelet/bubbletea`.
- Keep dependencies minimal. Ask before adding anything not listed here.
- Use `context.Context` everywhere; Ctrl-C must cancel scans cleanly.
- `golangci-lint` clean; `go vet` clean; table-driven tests.

---

## 3. Project Structure

```
sweep/
├── cmd/sweep/main.go              # entrypoint
├── internal/
│   ├── cli/                       # cobra commands (scan, report, clean, top, explain, doctor, rules)
│   ├── scanner/                   # concurrent filesystem walker + size accounting
│   ├── rules/                     # rule engine; rules defined in embedded YAML
│   │   └── builtin/*.yaml         # go:embed rule files, one per domain (node, xcode, docker, system…)
│   ├── classifier/                # applies rules to scan results → Findings with risk tier
│   ├── safety/                    # hardcoded protected paths, deletion guards (cannot be overridden)
│   ├── macos/                     # tmutil, diskutil, statfs, Full Disk Access detection, native cleanup cmds
│   ├── cleaner/                   # deletion planner + executor (trash / permanent / native command)
│   ├── report/                    # table, JSON, and summary renderers
│   ├── cache/                     # persist last scan to disk so `clean` can reuse it
│   └── audit/                     # append-only JSONL log of every deletion
├── testdata/                      # fixture trees for tests
├── Makefile
└── README.md
```

---

## 4. Commands

| Command | Purpose |
|---|---|
| `sweep doctor` | Check macOS version, Full Disk Access for the terminal, whether running as root, disk totals. Print fix instructions if FDA is missing. |
| `sweep scan [path]` | Scan (default: `/` handled correctly, see §5) and save results to cache. Shows summary when done. |
| `sweep` | Scan the home folder and show the summary (the one command a new user needs). |
| `sweep show [path]` | Read the last scan. No path: the report (disk overview, categories, reclaimable space by tier, top offenders). A folder: its contents with tiers. Any other path: what it is, which rule matched, its tier, and why (works for paths not in a rule). `--largest [--files\|--dirs]`: largest files/directories. Replaces the earlier `report`, `top`, `ls` and `explain`. |
| `sweep clean` | Build a deletion plan from the last scan (scanning the home folder first if there is none), show it, ask for confirmation, execute. |
| `sweep rules list` | Show all rules with category and tier. |

Global flags: `--json`, `--no-color`, `--verbose`, `--config <file>`.

`clean` flags:
- `--tier safe` (default) | `caution` (must be explicitly requested; never `review`/`protected`).
- `--category <name>` (repeatable), `--older-than 30d`, `--min-size 100MB`, `--exclude <glob>` (repeatable).
- `--dry-run` is the **default**. Real execution requires `--execute`, plus interactive `y/N` confirmation unless `--yes` is also passed.
- `--permanent` deletes instead of moving to Trash (still needs confirmation).
- `--interactive` lets me toggle individual items before execution.

---

## 5. Scanner Requirements

Correct numbers matter more than speed, but it must still be fast.

- **Concurrency:** bounded worker pool (default `runtime.NumCPU()*4`, flag-configurable) over `os.ReadDir`/`Lstat`. Aggregate sizes bottom-up per directory.
- **Allocated size, not apparent size:** use `syscall.Stat_t.Blocks * 512`. Report apparent size separately in verbose mode. Sparse files (e.g. `Docker.raw`) must show real on-disk usage.
- **Hard links:** count each `(dev, inode)` once.
- **Symlinks:** never follow.
- **APFS firmlinks / double counting:** on macOS, `/` (sealed system volume) and `/System/Volumes/Data` are joined by firmlinks, so a naive walk of `/` double-counts user data. Scan the data volume once and map paths back to their user-facing form (`/Users/...`, `/Applications/...`). Do not descend into `/Volumes`, `/dev`, `/System/Volumes/*` other than Data, or network mounts. Do not cross device boundaries unless asked.
- **APFS clones:** cloned files report full size each. Note this limitation in the report rather than trying to resolve it.
- **Permissions:** on `EPERM`/`EACCES`, record the path as "inaccessible" with its count, keep going, and surface a summary ("1,240 paths unreadable — grant Full Disk Access, see `sweep doctor`"). Don't require `sudo`; support it optionally for `/private/var/log` etc.
- **Early pruning:** when a directory matches a "whole directory" rule (e.g. `node_modules`), size it but don't emit its children as separate findings.
- **Output:** a tree of nodes `{path, size, apparentSize, fileCount, mtime, atime, isDir}` with top-N tracking, plus the list of rule matches. Persist to `~/Library/Caches/sweep/last-scan.json` (or gob/compressed) with scan timestamp and root.
- **Progress:** files scanned, bytes counted, current directory (throttled to ~10 updates/sec).

---

## 6. Risk Tiers

Every finding gets exactly one tier.

| Tier | Meaning | Cleanable by `clean`? |
|---|---|---|
| `SAFE` | Fully regenerable, no user state. Caches, build outputs, logs. | Yes (default) |
| `CAUTION` | Regenerable but costly or may hold state: virtualenvs, Docker images, simulators, Go module cache, old Xcode DeviceSupport. | Only with `--tier caution` |
| `REVIEW` | Likely user data that is large: Downloads, iOS backups, videos, VM disk images, Xcode Archives. | Never automatically; only listed for me to handle manually |
| `PROTECTED` | System or critical personal data. Shown so I understand usage. | Never. Hard-blocked in code. |

Unmatched paths default to `REVIEW` if under the home directory, `PROTECTED` elsewhere.

---

## 7. Rule Engine

Rules live in embedded YAML so new ones can be added without code changes. User rules from `~/.config/sweep/rules.yaml` may add rules or exclusions but **cannot** downgrade anything in the safety layer (§8).

Example schema:

```yaml
- id: node-modules
  category: "Dev: JavaScript"
  match:
    dir_name: node_modules
    require_sibling_any: [package.json]   # only if parent is a real project
  tier: SAFE
  description: "npm/yarn/pnpm dependencies. Recreated by reinstalling."
  regenerate_hint: "npm install / pnpm install"
  stale_after_days: 30                     # optional: flag projects untouched for N days

- id: go-build-cache
  category: "Dev: Go"
  match:
    path: "~/Library/Caches/go-build"
  tier: SAFE
  native_clean: ["go", "clean", "-cache"]  # prefer native command over rm
```

Match options to support: exact path (with `~` expansion), glob, directory name, file extension, `require_sibling_any` / `require_parent_marker` (e.g. `target` only if `Cargo.toml` exists next to it), min size, min age. Rules must be validated at startup with clear errors.

**Project staleness:** for dev artifacts, detect the project root and compute "last activity" (newest mtime among source files outside artifact dirs, or last git commit time if `.git` exists). Report "stale project artifacts" separately; they're the best cleanup candidates.

### Built-in rules to ship (categorized)

**Dev: JavaScript/TS** (SAFE unless noted): `node_modules`, `.next`, `.nuxt`, `.svelte-kit`, `.turbo`, `.parcel-cache`, `.vite`, `.angular/cache`, `.expo`, `coverage`, `dist`/`build`/`out` (only with a `package.json` sibling); caches `~/.npm/_cacache`, `~/Library/Caches/Yarn`, `~/Library/pnpm/store` (CAUTION), `~/.bun/install/cache`.

**Dev: Python:** `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.tox` (SAFE); `.venv`/`venv` with `pyvenv.cfg` inside (CAUTION); `~/Library/Caches/pip` (SAFE); conda `pkgs` cache (CAUTION).

**Dev: Go / Rust / JVM:** `~/Library/Caches/go-build` (SAFE, `go clean -cache`); `~/go/pkg/mod` (CAUTION, `go clean -modcache`); Rust `target/` with `Cargo.toml` sibling (SAFE); `~/.cargo/registry` (CAUTION); `.gradle`, `~/.gradle/caches` (CAUTION); `~/.m2/repository` (CAUTION).

**Dev: Apple / Xcode:** `~/Library/Developer/Xcode/DerivedData` (SAFE); `~/Library/Developer/Xcode/iOS DeviceSupport` (CAUTION); `~/Library/Developer/CoreSimulator/Devices` (CAUTION, prefer `xcrun simctl delete unavailable`); `~/Library/Developer/Xcode/Archives` (REVIEW); `Pods` with `Podfile` sibling (SAFE); `~/Library/Caches/CocoaPods` (SAFE).

**Containers & VMs:** Docker Desktop data `~/Library/Containers/com.docker.docker/Data/vms/*/data/Docker.raw` → never delete the file; report size and suggest/offer `docker system prune` (CAUTION, native only). Also detect OrbStack, Colima, UTM/Parallels/VMware images (REVIEW).

**Package managers:** Homebrew cache `~/Library/Caches/Homebrew` (SAFE, prefer `brew cleanup -s`); old Homebrew Cellar versions (report, suggest `brew cleanup`).

**System Data (macOS):**
- `~/Library/Caches/*` per app (SAFE, but warn if the owning app is currently running).
- `~/Library/Logs`, `/Library/Logs`, `/private/var/log` (SAFE; the last needs sudo).
- `~/Library/Logs/DiagnosticReports`, `/Library/Logs/DiagnosticReports` (SAFE).
- Time Machine local snapshots: list via `tmutil listlocalsnapshots /` and size estimation; offer `tmutil thinlocalsnapshots` (CAUTION, native only, needs confirmation).
- iOS/iPadOS backups `~/Library/Application Support/MobileSync/Backup` (REVIEW).
- Mail attachments cache `~/Library/Containers/com.apple.mail/Data/Library/Mail Downloads` (SAFE).
- `/private/var/vm` swap and sleepimage (PROTECTED: explain it's managed by macOS and shrinks on reboot).
- `/private/var/folders` (PROTECTED for deletion; report size and explain that a reboot clears much of it).
- Trash `~/.Trash` (SAFE, "empty Trash").

**User files (REVIEW only):** `~/Downloads` items older than N days, large media files (`.mov`, `.mp4`, `.mkv`, `.dmg`, `.iso`, `.zip` over 500 MB), old installers (`.dmg`, `.pkg`) anywhere in home.

---

## 8. Safety Layer (non-negotiable, implemented in Go, not YAML)

1. **Hardcoded protected roots** that block any deletion at or below them, whatever any rule says:
   `/System`, `/usr` (except `/usr/local` caches matched by rules), `/bin`, `/sbin`, `/private/etc`, `/private/var/db`, `/private/var/vm`, `/Library/Apple`, `/Applications/*.app` bundles, `~/Library/Keychains`, `~/Library/Mobile Documents` (iCloud Drive), `~/Library/Messages`, `~/Library/Mail` (data, not Downloads cache), `~/Pictures/*.photoslibrary`, `~/Library/Application Support/AddressBook`, `~/Library/Calendars`, `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.config`, any `.git` directory, any file named `.env*`, and the home directory itself.
2. **Deletion-time revalidation** (guards against stale scans and TOCTOU): right before deleting, re-`Lstat` the path, confirm it still exists, is not a symlink, is still matched by the same rule, is still within the scanned root, and is not inside a protected root. Skip and log on any mismatch.
3. **Path sanity:** reject empty paths, `/`, `~`, relative paths, paths containing `..` after cleaning, and anything shorter than 3 components under `/Users/<name>`.
4. **Trash first:** default deletion moves items to `~/.Trash` (handle name collisions). `--permanent` uses `os.RemoveAll` only after confirmation.
5. **Native commands preferred** when a rule defines `native_clean` (`go clean`, `brew cleanup`, `docker system prune`, `xcrun simctl`, `tmutil`). Show the exact command before running it.
6. **Size cap prompt:** if a plan exceeds 50 GB or 500 items, require typing the total size or `DELETE` to confirm.
7. **Audit log:** every action appended to `~/Library/Logs/sweep/history.jsonl` with timestamp, path, size, rule id, tier, method (trash/permanent/native), and result.
8. **Never auto-escalate privileges.** If sudo is needed, tell me the exact command to run.

Write the safety package **first**, with exhaustive tests, before the cleaner exists.

---

## 9. Report Output (`sweep show`)

Sections, in order:

1. **Disk overview** — total, used, free (from `statfs`), plus "scanned vs unaccounted" (unaccounted = snapshots, purgeable space, inaccessible paths). Explain the gap.
2. **Where your space is going** — categories sorted by size with a bar chart in the terminal, e.g. `Dev: JavaScript ████████ 48.2 GB`.
3. **"System Data" decoded** — the macOS-hidden pieces (caches, logs, snapshots, simulators, Docker, iOS backups, swap, `/private/var/folders`) with a one-line explanation each.
4. **Reclaimable space** — totals per tier: `SAFE: 61.4 GB`, `CAUTION: 38.0 GB`, `REVIEW: 22.7 GB`, `PROTECTED: 31.2 GB (not deletable)`.
5. **Top 20 cleanup candidates** — path, size, category, tier, last modified, why it's safe, how to regenerate.
6. **Stale projects** — project roots with old artifacts and total reclaimable per project.
7. **Largest items needing your judgment** (REVIEW tier).
8. **Protected (for your information)** — big protected items with explanations, so I know why they can't go.
9. **Next steps** — suggested commands, e.g. `sweep clean --tier safe --dry-run`.

Use human-readable sizes (base-10 GB to match Finder; mention this). Tier colors: SAFE green, CAUTION yellow, REVIEW blue, PROTECTED red. `--json` emits the same data structured.

---

## 10. Testing

- Fixture trees in `testdata/` and generated temp dirs (`t.TempDir()`), never real home paths. Inject the home directory and filesystem root via config so tests can redirect them.
- Safety tests: for every protected root, prove that no rule, user config, or flag can put it into a deletion plan. Include symlink-swap and path-traversal cases.
- Rule tests: table-driven, positive and negative (e.g. `build/` without a project marker must **not** match).
- Scanner tests: hard links counted once, symlinks not followed, sparse file allocated size, permission-denied directories recorded and skipped.
- Cleaner tests: dry-run changes nothing; trash moves handle name collisions; revalidation skips changed paths.
- Benchmarks for the walker on a large synthetic tree.

---

## 11. Build Phases (stop after each for review)

1. **Scaffold + safety package + tests.** Cobra skeleton, `doctor` command, protected-path logic with full test coverage.
2. **Scanner.** Concurrent walk, accurate sizing, firmlink handling, progress, cache file. `scan` and `top` working.
3. **Rules + classifier.** YAML schema, embedded built-in rules, project-marker and staleness detection, `rules list` and `explain`.
4. **Reporting.** Full `report` output and `--json`.
5. **Cleaner.** Plan → dry-run → confirm → trash/permanent, revalidation, audit log, native commands.
6. **macOS integrations.** Time Machine snapshots, Docker, Simulators, Homebrew, running-app detection for caches.
7. **Polish.** README with screenshots of output, Makefile (`build`, `test`, `lint`, `release`), optional bubbletea TUI for `clean --interactive`.

For each phase: summarize what you built, what's tested, and any decisions I should weigh in on.

---

## 12. Definition of Done

- `sweep scan / && sweep show` gives an accurate, readable picture of my disk in under ~2 minutes on a typical 500 GB SSD with Full Disk Access.
- Sum of category totals is within a few percent of `statfs` used space, with the remainder explained.
- `sweep clean` cannot delete anything PROTECTED or REVIEW under any combination of flags or config, proven by tests.
- Every deletion is reversible (Trash) by default and recorded in the audit log.
