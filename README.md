# sweep

A fast, safety-first disk analyzer and cleaner for macOS.

`sweep` scans your whole disk in seconds, explains where the space goes (including what macOS hides
inside "System Data"), sorts every finding by how safe it is to delete, and cleans only what you
approve: dry run by default, Trash first, every action logged and reversible.

```
$ sweep                  # scan your home folder (~10 s)
$ sweep show             # where the space goes, what is safe to remove
$ sweep clean            # preview the cleanup
$ sweep clean --execute  # do it (asks first; everything goes to the Trash)
$ sweep restore          # changed your mind? put it all back
```

Safety beats completeness: a false "safe to delete" is treated as a critical bug, a missed cleanup as
a minor one.

## Install

macOS 11 (Big Sur) or later, Apple Silicon or Intel. A single static binary of about 4 MB with no runtime
dependencies.

**Install script** (downloads the latest release, checks its SHA-256, installs to `~/.local/bin`):

```sh
curl -fsSL https://raw.githubusercontent.com/mishraprayash/macsweep/main/install.sh | sh
```

If that folder is not on your `PATH` yet, the script adds one line to your shell's startup file
(`~/.zshrc`, `~/.bash_profile` or fish's `conf.d`), once; open a new Terminal window afterwards.
`SWEEP_VERSION=v0.4.0` pins a release, `SWEEP_INSTALL_DIR=/somewhere/bin` changes where it goes, and
`SWEEP_NO_MODIFY_PATH=1` leaves your startup files alone.

**With Go** (1.23+):

```sh
go install github.com/mishraprayash/macsweep/cmd/sweep@latest
```

**By hand**: download `sweep-darwin-universal.tar.gz` (or the `arm64`/`amd64` one) and `SHA256SUMS`
from [Releases](https://github.com/mishraprayash/macsweep/releases), check it with
`shasum -a 256 -c SHA256SUMS --ignore-missing`, unpack, and put `sweep` on your `PATH`. Files
downloaded with a browser are quarantined by macOS; if it refuses to open the binary, run
`xattr -d com.apple.quarantine sweep` once. The install script and `go install` avoid this.

**From source**:

```sh
make build                 # → bin/sweep
make install               # copies to /usr/local/bin (PREFIX=... to change)
make release VERSION=1.0.0 # → dist/ arm64, amd64 and universal archives + SHA256SUMS
```

For complete numbers, give your terminal **Full Disk Access** (System Settings → Privacy & Security
→ Full Disk Access). `sweep doctor` checks this and shows how to fix it. sweep never needs `sudo`.

## Workflow

```sh
sweep                              # scan your home folder
sweep scan                         # or the whole disk (or any folder: sweep scan ~/code)
sweep show                         # the full picture
sweep show ~/code --depth 2        # browse a folder: sizes, tiers, what is cleanable
sweep show ~/code/app/.next        # one path: what it is, which rule, which tier, why
sweep show --largest --dirs        # largest folders (add a path to narrow it)
sweep clean ...                    # plan → confirm → Trash (see below)
sweep restore                      # put back what the last clean moved to the Trash
sweep rules                        # every rule sweep knows, and what each found
sweep doctor                       # permissions, macOS version, disk totals
```

Everything except `clean --execute` and `restore --execute` is read-only. Scanning writes only its own
cache file (`~/Library/Caches/sweep/last-scan.gob.gz`).

## Risk tiers

| Tier | Meaning | Cleaned? |
|---|---|---|
| `SAFE` | Fully regenerable, no user state: caches, build output, logs | yes (default) |
| `CAUTION` | Regenerable but costly or stateful: virtualenvs, Docker, simulators, module caches | only with `--tier caution` |
| `REVIEW` | Probably your data: old downloads, large videos, iOS backups, archives | never; listed for you |
| `PROTECTED` | System or critical personal data | never; hard-blocked in code |

Anything no rule recognises is `REVIEW` inside your home folder and `PROTECTED` outside it.

## Cleaning exactly what you want

`clean` is a **dry run** unless you pass `--execute`. Filters combine (all must match):

```sh
sweep clean --name node_modules --name .next      # only these folder names (globs work)
sweep clean --under ~/code/old-project            # only inside one folder
sweep clean --category "Dev: JavaScript"          # one category (see sweep rules)
sweep clean --rule rust-target --stale            # stale Rust build output only
sweep clean --older-than 90d --min-size 500MB     # big, long-untouched items
sweep clean --exclude "~/code/keep/**"            # leave something alone
sweep clean --tier caution                        # include CAUTION items too
sweep clean --snapshots --interactive             # also thin Time Machine local snapshots
sweep clean --interactive                         # untick items by number before confirming
```

`--older-than` uses a project's *last activity* for build artifacts. That is the newest source file
or git commit, ignoring `node_modules` and the like, so a recently reinstalled `node_modules` in an
abandoned project still counts as old.

```
$ sweep clean --name node_modules --name .next
Clean plan · scan of ~ · just now  [DRY RUN]

  #  SIZE     TIER  ACTION         PATH
  1  12.0 MB  SAFE  move to Trash  ~/code/web/.next
  2  11.0 MB  SAFE  move to Trash  ~/code/web/node_modules

Total: 23.0 MB in 2 items moved to the Trash (recoverable until you empty it).

Left out:
  5 other findings did not match your filters.

Dry run: nothing was changed.
To clean these items, run:
  sweep clean --name node_modules --name .next --execute
```

With `--execute`:

- **Confirmation.** You confirm with `y` (the default answer is No). `--yes` skips the prompt. Plans
  over 50 GB or 500 items always require typing the total size or `DELETE`.
- **Rechecks before each deletion.** Every item is checked again right before it is touched: it must
  still exist, not be a symlink, and be the same file or folder. It must also still be inside the
  scan root, still match the same rule, and still not be protected. Anything that changed since the
  scan is skipped and logged.
- **Contents check.** Folders containing a `.git` repository or `.env*` file are refused, except
  inside `node_modules`.
- **Trash first.** Items move to `~/.Trash`, renamed `name 2`, `name 3` instead of overwriting.
  `--permanent` deletes instead.
- **Native commands.** Some items are cleaned by their own tool instead of deleting files: `go clean
  -cache`, `brew cleanup`, `docker system prune`, `xcrun simctl delete unavailable`, `tmutil
  thinlocalsnapshots`. The plan shows the exact command first, and `--skip-native` turns all of
  them off.
- **Running apps and open files.** Caches of apps that are running are skipped, and so is anything
  with a file some process has open (checked with `lsof` when planning and again just before cleaning;
  if that check cannot run, nothing is cleaned).
- **Audit log.** Every action is appended to `~/Library/Logs/sweep/history.jsonl`, including where
  each trashed item went. `sweep restore` uses it to move a session's items back. Finder's
  "Put Back" does not know about them.

## The report

`sweep show` (or `--json`) has nine sections:

1. **Disk overview.** Used vs scanned, with the gap explained: other APFS volumes (Preboot,
   Recovery, VM) by name, then snapshots, purgeable space and unreadable paths.
2. **Where your space is going.** Categories with bar charts. They add up exactly to the scanned
   total.
3. **"System Data" decoded.** Caches, developer caches, logs, simulators, Docker, iOS backups, temp
   files, swap, support volumes, snapshots.
4. **Reclaimable space** per tier.
5. **Top cleanup candidates**, with why each is safe and how to regenerate it.
6. **Stale projects**, grouped by project (monorepos included) with reclaimable size.
7. **Items needing your judgment** (`REVIEW`), including big files no rule knows.
8. **Protected items**, with why they can't go.
9. **Next steps**, the commands worth running next.

```
$ sweep show ~/code/web/node_modules
~/code/web/node_modules
  Tier        SAFE  fully regenerable, no user state
  Rule        node-modules · Dev: JavaScript  (builtin/javascript.yaml)
  Why         directory named node_modules; package.json next to it
  What        npm/yarn/pnpm dependencies. Recreated by reinstalling.
  Regenerate  npm install / pnpm install / yarn
  Project     ~/code/web · last activity 2026-10-07 (just now)
  Size        11.0 MB (scan from just now)
  Clean       Included in 'sweep clean' by default; moved to the Trash.

$ sweep show ~/code --depth 2
~/code  58.0 MB · 9 files · scan from just now
SIZE     SHARE  CLEANABLE  TIER     NAME
23.0 MB  40%    23.0 MB    -        web/
12.0 MB  21%    12.0 MB    SAFE       .next/
11.0 MB  19%    11.0 MB    SAFE       node_modules/
20.0 MB  34%    20.0 MB    -        api/
20.0 MB  34%    20.0 MB    SAFE       target/
15.0 MB  26%    15.0 MB    -        ml/
15.0 MB  26%    15.0 MB    CAUTION    .venv/

Findings here: SAFE 43.0 MB (3) · CAUTION 15.0 MB (1)
Preview a cleanup of just this folder: sweep clean --under ~/code
```

Sizes are base-10 (1 GB = 10⁹ bytes), matching Finder.

## Rules

100 built-in rules cover the usual places a Mac fills up:

- **App caches**: `~/Library/Caches`, caches of sandboxed App Store apps (`~/Library/Containers`,
  `Group Containers`), and the caches Electron apps and Chromium browsers keep in
  `Application Support` (VS Code, Slack, Discord, Notion, Teams, Postman, Chrome, Arc, ...):
  web cache, GPU/code caches, service-worker offline copies (CAUTION), crash dumps, VS Code's
  extension and startup caches, and editor state for folders unopened for 90+ days (CAUTION).
  Caches of apps that are running are skipped.
- **Leftovers of uninstalled apps** (CAUTION): data in `Application Support`, `Containers`,
  `Group Containers`, `WebKit` and `HTTPStorages` that clearly belongs to one app that is gone.
  "Clearly" means one of: named by its bundle ID or app group, an Electron app's data folder, or a
  folder named after an app that left its settings in `~/Library`. "Gone" means:
  - no app, launchd job or helper from that vendor is installed, and Spotlight knows none;
  - for app groups, also that no installed app declares the group in its code signature;
  - nothing inside has changed for 30 days (checked again right before cleaning).

  If Spotlight is off or a signature can't be read, nothing is offered.
- **JavaScript/TypeScript**: `node_modules`, `.next`, `.nuxt`, `.output`, `.svelte-kit`, `.turbo`,
  `.vite`, `.astro`, `.docusaurus`, `.cache`, `dist`/`build` next to a `package.json`; npm, npx,
  yarn, pnpm and bun caches; old nvm Node versions (the default and the active one are kept).
- **Other project types**: Rust `target`, Maven `target`, Gradle/Android `build`, Swift `.build`,
  Flutter `build`/`.dart_tool`, CMake, Elixir, Haskell, Zig, Unity, Godot, Terraform, PHP `vendor`,
  Python `build`/`dist`/`*.egg-info`, `__pycache__` and tool caches, virtualenvs.
- **Toolchains and package caches**: Go build and module caches (also stray `go-build` copies),
  Cargo, Gradle (and its downloaded distributions), Maven, NuGet, pip, uv, conda, Dart pub,
  PlatformIO, Android SDK caches, `~/.cache/*`, old Claude Code releases.
- **Xcode**: DerivedData, DeviceSupport, simulators, previews, device logs, Archives.
- **Containers and VMs**: Docker, OrbStack, Colima, UTM, Parallels, VMware.
- **Homebrew**: its cache and old formula versions.
- **macOS**: logs and crash reports, Mail attachments, Trash, iOS backups and software updates,
  swap, `/private/var/folders`, `/Library/Caches`.
- **Listed for you to review, never cleaned automatically**: AI models (Hugging Face, Ollama,
  LM Studio, PyTorch, Whisper), the Claude desktop VM image, pipx tools, pyenv/rbenv/rustup
  versions, Android emulator images, games, GarageBand/Logic sound libraries, old downloads,
  large media and old installers.

See them all, with what each one found in your last scan:

```sh
sweep rules                       # every rule, grouped by category, with sizes found
sweep rules --found               # only rules that found something
sweep rules chrome                # search ids, categories, descriptions and paths
sweep rules --tier safe           # one tier (also --category "App caches")
sweep rules show node-modules     # one rule in detail, with its largest findings
```

Name-based rules only fire with a project marker: `build/` needs a `package.json` beside it,
`target/` needs a `Cargo.toml`, `.venv` needs a `pyvenv.cfg`. They also only fire in your own
folders, never inside `~/Library`, app bundles or tool directories like `~/.vscode`, where those
names belong to installed software. The app-cache rules are the exception, and work the other way
round: they only fire under `~/Library`, and only next to Chromium's own profile files
(`Local State`, `Preferences`), so a folder that merely happens to be called `Cache` is left alone.

Add your own in `~/.config/sweep/rules.yaml` (or `--config <file>`):

```yaml
rules:
  - id: my-scratch-builds
    category: "Mine"
    match:
      glob: "~/scratch/*/out"
    tier: SAFE
    description: "Throwaway build output"
exclude:                # never clean these (matches become REVIEW)
  - "~/code/keep-forever/**"
```

Match options: `path`, `glob` (`*`, `**`), `name`, `dir_name`, `ext`, plus `type`, `under`,
`require_sibling_any`, `require_parent_marker`, `require_child_any`, `min_size`, `min_age_days`,
`project`, `user_files`. Rules are validated at startup and unknown fields are errors. User rules
cannot run commands and cannot loosen the safety layer.

## Safety layer

Hardcoded in Go (`internal/safety`), not configurable. Deletion is blocked at, below, and *above* (an
ancestor would take them along):

- `/System`, `/usr` (except cache folders under `/usr/local`), `/bin`, `/sbin`, `/private/etc`,
  `/private/var/db`, `/private/var/vm`, `/Library/Apple`, app bundles;
- Keychains, iCloud Drive, Messages, Mail, Photos libraries, Contacts, Calendars;
- `~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.kube`, `~/.config`, sweep's own audit log;
- any `.git` directory and any `.env*` file, and your home folder itself.

Paths are compared case-insensitively, as APFS does, with symlinked parents resolved. Shallow paths
(`/`, `~`, `~/Downloads`) and relative or `..` paths are rejected. The cleaner re-checks all of this
right before every deletion, so a stale or edited scan file cannot sneak anything through. Tests
prove that no rule, user config or flag gets a protected path into a plan.

## How it is fast

- **Batched directory reads.** Directories are read with `getattrlistbulk(2)`, which returns names
  and attributes for many entries per system call instead of one `lstat` per file. That makes
  directory reads 2.9× faster, with a readdir+lstat fallback for other filesystems.
- **Relative opens.** Subdirectories are opened relative to their parent (`openat`), so paths are
  not re-resolved.
- **Bounded parallelism.** About 1.5× the core count, measured: more workers only add kernel
  contention.
- **Cheap rule matching.** The no-match path does no allocation and costs about 0.5 µs per entry.
- **Sizes from disk blocks.** Sizes are allocated blocks, so sparse files like `Docker.raw` show real
  usage. Hard links count once, symlinks are never followed, and the sealed system volume and
  firmlinked data volume are walked once each, never double-counted.
- **Small saved scan.** About 0.7 MB for a full disk, so `show` and `clean`
  plans all take well under 0.1 s.

## Limitations

- APFS clones are counted at full size for each copy.
- Local Time Machine snapshot sizes are not exposed by macOS. They are part of the "unaccounted"
  space in the disk overview.
- `/private/var/log` and some system logs need `sudo` to delete. sweep tells you the command but never
  escalates.
- The saved scan keeps folders of 1 MB or more (totals are always complete).

## Development

```sh
make test     # all tests (sandboxed: temp dirs, $HOME redirected)
make race     # with the race detector
make lint     # golangci-lint
make bench    # scanner benchmarks
make demo     # full scan → report → clean → restore walkthrough in a throwaway sandbox
```

No test or demo touches your real files. `testutil.NewSandbox` puts everything in a temp dir and
points `$HOME` there. `testutil.AssertReadOnlyPackage` statically forbids filesystem writes in the
scanner, rules, classifier and report packages. Native commands are replaced by recorders in tests.

```
cmd/sweep          entry point
internal/cli       commands
internal/scanner   concurrent walker (getattrlistbulk), firmlink handling
internal/rules     YAML rule engine + built-in rules (builtin/*.yaml), nvm/Claude version detector
internal/classifier rules → findings, tiers, staleness, Homebrew detector
internal/safety    protected paths and deletion guards
internal/cleaner   plan, revalidate, Trash/delete/native, restore
internal/report    report model and renderers
internal/macos     statfs, APFS volumes, snapshots, Full Disk Access, running apps
internal/cache     saved scan
internal/audit     append-only JSONL log
internal/testutil  sandbox, fixtures, read-only checks
```

## License

[MIT](LICENSE)
