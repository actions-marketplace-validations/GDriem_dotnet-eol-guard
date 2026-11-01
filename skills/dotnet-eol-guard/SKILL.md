---
name: dotnet-eol-guard
description: Audit and upgrade .NET repositories that run on an end-of-life or soon-unsupported runtime (.NET Core 1-3.1, .NET 5, 6, 7, 8, 9, old .NET Framework), on an unpatched runtime with known CVEs, or depend on NuGet packages with known vulnerabilities or deprecations. Use when the user asks to upgrade .NET, migrate to .NET 10 / the current LTS, fix vulnerable or deprecated NuGet packages, asks whether a specific CVE affects their .NET project, check .NET support dates or EOL, fix NU1901-NU1904 audit warnings, or update Dockerfiles and CI pipelines to a supported or patched .NET version.
license: MIT
---

# dotnet-eol-guard

Upgrade a .NET repository to a supported runtime and remove known-vulnerable packages, safely and verifiably.
The work is split in two: a deterministic scanner (`scripts/eol-guard.cs`) says **what** is wrong; this playbook
says **how** to fix it. Never skip the scanner and never claim success without re-running it.

## Ground rules

- Work on a new branch of a clean git tree. Do not commit, push or open PRs unless the user asks.
- Keep the change minimal: retarget, bump, fix what breaks. No refactors, renames or style changes.
- Never "fix" a build by suppressing warnings broadly, disabling `NuGetAudit`, deleting or skipping tests,
  or lowering `TreatWarningsAsErrors`. A targeted suppression needs a one-line justification next to it.
- Target the newest **LTS** the scanner recommends. Use an STS or preview only if the user asks for it.
- Stop and ask the user before: migrating .NET Framework to modern .NET, a major bump of a package whose
  license changed (see `references/breaking-changes.md`), anything touching a database schema, or upgrades in
  a repository with more than ~20 projects (agree on the order first).
- Do not read or print secrets (`appsettings.*.json` with credentials, `.env`, user secrets).
- Preserve each file's line endings (CRLF or LF) and encoding. A whole-file diff from newline
  normalization hides the real change; check `git diff --stat` after every batch of edits.
- Never run `dotnet ef migrations remove --force`: it can delete a real migration.

## Delegation (optional, saves tokens)

If your agent can start sub-agents, act as the **orchestrator**. You keep the plan, the user's decisions,
the shared files and the final report. Each step that produces bulky output goes to a sub-agent on the
cheapest model that can do it, and the sub-agent returns a short, fixed-format summary. Scanner JSON,
build logs and test output then never enter your context.

| Step | Role | Model tier | Claude Code agent | Codex agent |
|---|---|---|---|---|
| 2. Scan | Run the scanner, condense findings into work units | fast/cheap (Haiku / GPT Luna class) | `eol-scanner` | `eol_scanner` |
| 4. Baseline, 7-8. Verify | Build, test, re-scan, compare numbers; never edits | fast/cheap | `eol-verifier` | `eol_verifier` |
| 5. Upgrade | Mechanical edits + one build for **one work unit** | mid (Sonnet / GPT Sol medium) | `eol-upgrader` | `eol_upgrader` |
| 6. Build errors | Errors the upgrader could not fix | mid; strongest model/effort only after it fails twice | `eol-build-fixer` | `eol_build_fixer` |
| 3, 5.1-5.3 shared files, 9 | Plan, user decisions, shared files, final report | you | — | — |

If those agents are not installed, start generic sub-agents with the same instructions (from the repository's
`agents/` folder) and pick the model tier explicitly when spawning them.

Rules:

- **Do not delegate small jobs.** With 3 or fewer projects and fewer than about 10 findings, do it yourself:
  starting sub-agents costs more than it saves.
- Give each sub-agent everything it needs in the prompt: repository path, skill directory, output directory,
  target, its exact files, and the reply format. It cannot see your conversation. It returns questions to you;
  only you talk to the user.
- **You edit the shared files first**: `global.json`, `Directory.Build.props`, `Directory.Packages.props`. After
  that, upgraders can work on work units **in parallel only if their file sets are disjoint**. Never run two
  restores, builds or test runs in the same repository at the same time; `obj/` and NuGet assets collide.
  Run the builds one after another.
- Use a **fresh** `eol-verifier` for the final check, never the agent that made the edits, so the numbers come
  from an independent run.
- Escalate the model, not the scope. If the fixer fails twice on the same error, rerun it on the strongest
  model with only that error. Do not hand it the whole repository.
- When a sub-agent reports a `NEW PITFALL`, pass it on to the user as a candidate for
  `references/breaking-changes.md`.

Without sub-agents, follow the same steps yourself and still filter command output (`grep`, `jq`, `tail`) as
shown below.

## Workflow

### 1. Preconditions

```bash
dotnet --list-sdks             # needs the target SDK (10.0.x); the scanner itself needs .NET 10+
git -C <repo> status --short   # must be clean
git -C <repo> checkout -b chore/dotnet-eol-upgrade
```

If the target SDK is missing, stop and tell the user to install it from https://dotnet.microsoft.com/download.
Also note whether the SDK the repo builds with today is installed (see `global.json`, or the TFM if there
is none); the baseline in step 4 needs it.

### 2. Scan

Run the scanner **from its own folder** and pass the repository as an absolute path. If you run it inside a
repository whose `global.json` pins an old SDK, `dotnet` picks that SDK and cannot run single-file apps.

```bash
cd <skill-dir>/scripts
dotnet run eol-guard.cs -- --path <repo-abs-path> --format json --out <tmp>/eol-before.json
dotnet run eol-guard.cs -- --path <repo-abs-path> --out <tmp>/eol-before.md
```

Useful flags: `--cve CVE-A,CVE-B` (the user named specific CVEs), `--installed` (also check the runtimes
installed on this machine, for servers and VMs), `--fail-on none` (report only), `--no-packages` (fast, no restore), `--as-of 2026-11-11`
(what will be unsupported by then), `--target 10.0`, `--offline`. Write the reports outside the repository.

Read the report. Categories:

| Category | Meaning | Where to fix |
|---|---|---|
| `runtime` | `TargetFramework(s)` on an unsupported or expiring channel | `.csproj`, `Directory.Build.props` |
| `sdk` | `global.json` pins an old SDK | `global.json` |
| `container` | Base image of an old channel or the retired `microsoft/*` Docker Hub repos | `Dockerfile`, compose, k8s YAML, devcontainer |
| `ci` | Pipeline installs an old SDK | `.github/workflows`, `azure-pipelines.yml`, `.gitlab-ci.yml` |
| `package-runtime` | Microsoft.AspNetCore/EntityFrameworkCore/Extensions.* (and EF providers) tied to an old runtime | project files or `Directory.Packages.props` |
| `package-vulnerable` | Package with a published advisory (direct or transitive) | see step 5 |
| `package-deprecated` | Package marked deprecated, often with a suggested replacement | see step 5 |
| `runtime-patch` | Supported channel, but a pinned patch (image tag `10.0.13`, `RuntimeFrameworkVersion`, `global.json` SDK) is older than a release that fixed CVEs in the runtime itself | see step 5.6 |
| `installed-runtime` | (`--installed`) a runtime on this machine is out of support or missing security patches | update the machine, not the repo |
| `cve` | (`--cve`) whether each requested CVE is a .NET runtime fix and what in the repo is exposed | see "Specific CVEs" below |
| `package-audit` | Could not audit (restore failed, `packages.config`) | fix restore, or tell the user |

### 3. Plan and confirm

Summarize to the user, per project: current → target framework, packages to bump, vulnerable packages and
their fix, files outside code (Docker, CI) and anything that needs a decision (ground rules). Wait for an OK
when there is a decision to make; otherwise proceed.

### 4. Baseline

Before changing anything, build and test **with the SDK the repo uses today**. If there is no `global.json`
and the default `dotnet` is a different (often newer, sometimes preview) SDK, write a temporary
`global.json` pinning the current one; step 5 replaces it with the target pin, so it does not linger.

```bash
dotnet --version                                   # confirm which SDK is in use
dotnet build <solution-or-project> -c Release 2>&1 | grep -E "Warn|Error\(s\)|error " | tail -n 20
dotnet test <solution-or-project> -c Release --no-build 2>&1 | grep -E "Passed!|Failed!|Total tests|Failed " | tail -n 20
```

Record the warning count, errors and passed/failed/skipped per test project. Tests that need external
services (databases, containers) or depend on today's date may fail in the baseline too; list them so
they are not blamed on the upgrade.

### 5. Upgrade, in this order

0. **Known breaking changes first.** Read the section of `references/breaking-changes.md` for your target
   and the versions you are coming from, and list the items that apply to packages and APIs this repo
   uses (for .NET 10: Swashbuckle/OpenAPI, `.WithOpenApi()`, `RedisValue` casts, container OS/UID...).
   Apply them as part of this step instead of waiting for the build to fail.
1. **SDK pin.** Create or update `global.json` with the target SDK that is installed
   (`"version": "10.0.xxx"`, `"rollForward": "latestFeature"`). Create it even if the repo had none, so the
   build does not drift to a newer or preview SDK.
2. **Target framework.** Edit it where it is defined: if `Directory.Build.props` sets it, change it there
   once. Keep platform suffixes (`net8.0-windows` → `net10.0-windows`). For multi-targeted libraries,
   replace the expired TFM and keep `netstandard2.0` if it is there for consumers.
3. **Runtime-aligned packages.** Every `Microsoft.AspNetCore.*`, `Microsoft.EntityFrameworkCore*`,
   `Microsoft.Extensions.*`, `System.Text.Json` and EF providers (`Npgsql.EntityFrameworkCore.PostgreSQL`,
   `Pomelo.EntityFrameworkCore.MySql`) move to the latest **patch of the target major**, all to the same
   version. With Central Package Management edit `Directory.Packages.props`.
   Find versions with `dotnet package search <id> --exact-match` or `dotnet list package --outdated`.
4. **Vulnerable packages.**
   - Direct: bump to the first patched version in the advisory (prefer the latest patch of the same major;
     a new major only if no patch exists, and then check its changelog and license).
   - Transitive: first bump the top-level package that brings it in (`dotnet nuget why <project> <id>`
     shows the path). If none fixes it, add a direct `PackageReference` to the patched version, or with
     CPM enable `CentralPackageTransitivePinningEnabled` and add a `PackageVersion`.
5. **Deprecated packages.** Replace only when the report gives a drop-in alternative and the change is
   small. Otherwise list them as follow-ups for the user; deprecation is not a vulnerability.
6. **Containers and runtime patches.** Same image repo, new tag (`aspnet:9.0` → `aspnet:10.0`). Keep
   variants the project chose deliberately (`-alpine`, `-chiseled`, `-noble`). Read the container notes in
   `references/breaking-changes.md` (default OS and users change between versions).
   For `runtime-patch` findings: raise pinned patch tags to the latest patch (`aspnet:10.0.13` →
   `10.0.14`), raise or remove `RuntimeFrameworkVersion`, and pin the latest SDK in `global.json`.
   Runtime CVEs (e.g. in the bundled Brotli or zlib) are **not** NuGet packages: no `PackageReference`
   change fixes them. Tell the user that floating tags (`aspnet:10.0`) are only patched once the image
   is rebuilt with `--pull` and redeployed, and that framework-dependent apps on VMs/IIS need the runtime
   updated on each server (`--installed` on that machine shows it).
7. **CI.** `actions/setup-dotnet` `dotnet-version`, Azure `UseDotNet@2` `version`, `DOTNET_VERSION`
   variables, and any matrix that lists SDKs.
8. **Docs.** README lines that state the required SDK/runtime.

### 6. Build, fix, repeat

Build after the changes. For each error, check `references/breaking-changes.md` first, then the official
breaking-change list for the target version (linked there). Fix the cause in code. Repeat until the build is
clean and the warning count is not worse than the baseline (new obsoletion warnings are expected; fix the
ones with a clear replacement and list the rest).

If the project uses EF Core, check for model drift. Update the tool first
(`dotnet tool update -g dotnet-ef` or the local tool manifest) so it matches the new EF major. Then:

```bash
dotnet ef migrations has-pending-model-changes --project <proj> --startup-project <startup> --configuration Release
```

(`-c` means `--context` in `dotnet ef`, not configuration.) Creating the DbContext at design time may need
a connection string from an environment variable, e.g. `ConnectionStrings__Default="Host=localhost;..."`;
the command does not connect to the database. If the check reports changes, stop and show the user; do
not generate or ship a migration. If you used `migrations add` to inspect a diff instead, delete the
generated files by hand and `git checkout -- <Migrations folder>`; never use `migrations remove --force`.

### 7. Test

Run the tests with the same commands as the baseline. Passed must be ≥ baseline and nothing that passed
before may fail now. Investigate every new failure; do not mark tests as skipped. Test code is part of the
upgrade: filters, mocks and assertions that use changed APIs (e.g. OpenAPI models) must be ported too.

### 8. Verify

```bash
cd <skill-dir>/scripts && dotnet run eol-guard.cs -- --path <repo-abs-path> --out <tmp>/eol-after.md
```

Expected: no `critical` or `high` findings left. Anything that remains needs an explicit reason
(e.g. "no patched version published yet", "needs a team decision").

### 9. Report to the user

Whenever something runs on an out-of-support version, say so in plain words at the top of the report and
in the plan (step 3). Microsoft no longer patches it, so this and any future vulnerability stays open, and
bumping packages does not change that. The recommendation is to migrate to the target version. Never
present an out-of-support runtime as "fixed" because its packages were updated.

- Before/after summary from the two scans (counts per severity).
- What changed, grouped: framework, packages, vulnerabilities fixed (with advisory links), Docker, CI.
- Build and test results vs baseline.
- Runtime behavior changes to watch when deploying (from `references/breaking-changes.md`), especially
  container OS/user changes and anything that only fails at runtime.
- Follow-ups: deprecated packages, decisions left to the user, leftover findings.
- Confirm `git status` shows only intended changes (no stray reports, throwaway migrations, or
  line-ending-only diffs).

## Specific CVEs

When the user asks about named CVEs, run the scanner with `--cve <ids>` (add `--installed` if they run apps
directly on this machine) and answer per CVE:

- **Fixed in a .NET release** (`cve` finding lists the runtime versions): say which items are exposed.
  Items on a supported version are fixed by updating to the patched version (step 5.6), then rebuilding and
  redeploying. Items on an **out-of-support** version will never get the fix: tell the user plainly and
  recommend migrating them to the target with this workflow. If nothing is pinned, explain what still needs action
  outside the repo (image rebuilds, server updates).
- **Not in any .NET release**: it is not fixed by a .NET update. If the package audit shows a matching
  advisory, fix the package (step 5.4). Otherwise say plainly that it belongs to another product (for
  example a Windows component, fixed by Windows Update) and that this skill cannot fix it. Do not invent
  code changes for it.

## References

- `references/breaking-changes.md`: known pitfalls by target version, licensing traps, official links.
- `scripts/eol-guard.cs`: the scanner; `dotnet run scripts/eol-guard.cs -- --help` for all options.
