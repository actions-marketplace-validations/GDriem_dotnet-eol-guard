# dotnet-eol-guard

**.NET 8 and .NET 9 both lose support on November 10, 2026.** After that date they get no security patches.
`dotnet-eol-guard` finds every place a repository depends on an unsupported .NET version or a vulnerable
NuGet package, and gives any AI coding agent a tested playbook to fix it and prove the fix.

[Español](README.es.md)

```text
| Severity    | Findings |
|-------------|----------|
| 🔴 Critical | 5        |   net6.0 TFM, sdk:6.0 / aspnet:6.0 images, JwtBearer 6.0.0, setup-dotnet 6.0.x
| 🟠 High     | 8        |   net8.0 + global.json 8.0 (EOL in 9 days), Newtonsoft.Json 12.0.1 (GHSA-5crp-9r3c-p9vr)…
| 🟡 Medium   | 2        |   transitive System.IdentityModel.Tokens.Jwt 6.10.0
| 🔵 Low      | 7        |   deprecated WindowsAzure.Storage…
```

## What it checks

| Where | What |
|---|---|
| `*.csproj`, `Directory.Build.props` | `TargetFramework(s)` on EOL or soon-EOL channels (.NET Core 1.0 → .NET 9, old .NET Framework) |
| `global.json` | Pinned SDK channel |
| `Dockerfile`, compose, Kubernetes YAML, devcontainer | `mcr.microsoft.com/dotnet/*` tags and the retired `microsoft/dotnet` Docker Hub images |
| GitHub Actions, Azure Pipelines, any YAML | `setup-dotnet` versions, `UseDotNet@2`, `DOTNET_VERSION` variables |
| `PackageReference` / `Directory.Packages.props` | ASP.NET Core, EF Core, `Microsoft.Extensions.*` and EF providers stuck on an old runtime major |
| NuGet (direct **and transitive**) | Known vulnerabilities (GitHub Advisory Database via `dotnet list package --vulnerable`) and deprecations |
| Pinned patch versions | Image tags like `aspnet:10.0.13`, `RuntimeFrameworkVersion`, the `global.json` SDK: flagged when a newer patch fixed CVEs **in the runtime itself**, which no NuGet audit sees |
| This machine (`--installed`) | Installed runtimes that are out of support or missing security patches |

Support dates come live from Microsoft's official
[`releases-index.json`](https://builds.dotnet.microsoft.com/dotnet/release-metadata/releases-index.json),
so the tool stays correct when the next version goes out of support. A built-in snapshot is used offline.

## Two parts, any AI

1. **Scanner** (`skills/dotnet-eol-guard/scripts/eol-guard.cs`): a single C# file, no AI involved,
   no dependencies. It reads your repo, never edits it, and prints a Markdown or JSON report with an exit
   code you can use in CI.
2. **Playbook** (`skills/dotnet-eol-guard/SKILL.md`): step-by-step instructions any coding agent can follow:
   scan → plan → build/test baseline → upgrade in a safe order → fix breaking changes → tests → re-scan →
   report. It includes a list of real pitfalls ([`references/breaking-changes.md`](skills/dotnet-eol-guard/references/breaking-changes.md)):
   OpenAPI 2.x / Swashbuckle 10, C# 14 overload ambiguities, Ubuntu-based .NET 10 images, port 8080, and
   packages that turned commercial (MediatR, AutoMapper, MassTransit, FluentAssertions).

`SKILL.md` follows the open [Agent Skills](https://agentskills.io) format, so it works with Claude Code,
OpenAI Codex, GitHub Copilot, Cursor and others. Any assistant that can read a file can follow it.

## Quick start

Requires the [.NET 10 SDK](https://dotnet.microsoft.com/download) (you need it for the upgrade anyway).

### Just scan

```bash
git clone https://github.com/GDriem/dotnet-eol-guard
cd dotnet-eol-guard/skills/dotnet-eol-guard/scripts
dotnet run eol-guard.cs -- --path /path/to/your/repo
```

Run it from the `scripts` folder: if you run it inside a repo whose `global.json` pins an older SDK,
`dotnet` picks that SDK and it cannot run single-file apps.

| Option | Default | |
|---|---|---|
| `--format md\|json` | `md` | Report format |
| `--out <file>` | stdout | Write the report to a file |
| `--fail-on <level>` | `high` | `critical`, `high`, `medium`, `low` or `none`; exit code 1 when reached |
| `--warn-days <n>` | `180` | Flag channels that lose support within n days |
| `--as-of <date>` | today | "What will be unsupported on 2026-11-11?" |
| `--target <x.y>` | newest LTS | Channel to recommend |
| `--no-packages` | | Skip the NuGet audit (no restore, seconds instead of minutes) |
| `--no-restore` | | Audit without running `dotnet restore` first |
| `--cve <ids>` | | Answer "does CVE-X affect this repo?": runtime fix or not, and what is exposed |
| `--installed` | | Also check the runtimes installed on this machine |
| `--offline` | | Use the built-in lifecycle snapshot (no patch-level or CVE checks) |

### Fix it with an AI agent

Install the skill, then ask your agent: *"Upgrade this repo off unsupported .NET and fix vulnerable packages
using the dotnet-eol-guard skill."*

| Agent | Install |
|---|---|
| Claude Code | `/plugin marketplace add GDriem/dotnet-eol-guard` then `/plugin install dotnet-eol-guard@dotnet-eol-guard`, or copy `skills/dotnet-eol-guard` to `~/.claude/skills/` |
| GitHub Copilot (VS Code / Visual Studio) | copy `skills/dotnet-eol-guard` to `.github/skills/` in your repo or `~/.copilot/skills/` |
| OpenAI Codex | copy `skills/dotnet-eol-guard` to `.agents/skills/` in your repo, and `codex/agents/*.toml` to `.codex/agents/` |
| Several agents in one repo | `.agents/skills/dotnet-eol-guard/` is read by many of them |
| Anything else | add [`adapters/AGENTS.md.snippet`](adapters/AGENTS.md.snippet) to your `AGENTS.md`, or paste [`adapters/prompt.md`](adapters/prompt.md) into the chat |

**Token-saving delegation.** For bigger repositories the playbook delegates bulky work to sub-agents on the
cheapest model that can do it. Scanning and verification run on a Haiku-class model and the mechanical upgrade
of each work unit on a Sonnet-class model. The strongest model only gets build errors that resisted two tries.
The orchestrator only sees short summaries, never raw scanner JSON or build logs. The Claude Code plugin ships
these as ready-made agents (`agents/`: `eol-scanner`, `eol-upgrader`, `eol-build-fixer`, `eol-verifier`). If you
install by copying, also copy `agents/*.md` to `~/.claude/agents/` or `.claude/agents/`.
For **OpenAI Codex**, copy `codex/agents/*.toml` to `.codex/agents/` (project) or `~/.codex/agents/` (personal).
They use `gpt-6-luna` for scan/verify and `gpt-6.1-sol` for edits and build fixes. If your account has other models,
change `MODELS` in `tools/gen-codex-agents.py` and run it. Other agents with sub-agent support follow the
same roles from `SKILL.md`.

The playbook keeps the agent on a short leash: minimal changes, no blanket warning suppression, no disabled
NuGet audit, no skipped tests, and it must ask before migrating .NET Framework, bumping a package into a
commercial license, or touching a database schema.

### In CI

```yaml
- uses: actions/checkout@v4
- uses: GDriem/dotnet-eol-guard@v0.1.0
  with:
    fail-on: high      # critical | high | medium | low | none
```

The report goes to the job summary. Schedule it weekly too: new CVEs and EOL dates show up without any
code change. Full example: [`examples/github-workflow.yml`](examples/github-workflow.yml).

## Tested on

- `tests/fixtures/legacy-app`: .NET 6/8 API with vulnerable and deprecated packages (`tests/run.sh`).
- `tests/fixtures/patched-app`: .NET 10 with pinned patches older than the October 2026 security release.
- A real-world .NET 9 Web API (4 projects, ~890 tests): an agent that only had `SKILL.md` upgraded it to
  .NET 10. The scan went from 20 high findings to 0, the build went from 10 warnings to 9, and the test results matched
  the baseline exactly. Its feedback (EF drift check, baseline SDK, OpenAPI 2.x in tests) is already folded
  into the playbook.

## Limitations

- `packages.config` projects cannot be audited by the .NET CLI; the report says so.
- The NuGet audit needs a successful `dotnet restore` (access to private feeds, the right SDK installed).
- Values that come from MSBuild properties or Docker build args are reported as "cannot check statically".
- .NET MAUI and mobile workloads have their own support policy; the report links it.
- .NET Framework → modern .NET is flagged but never automated.

## Contributing

Issues and PRs are welcome, especially new entries for `references/breaking-changes.md` from real upgrades.
Run `tests/run.sh` before sending a PR.

## License

[MIT](LICENSE) © Gadi Orellana
