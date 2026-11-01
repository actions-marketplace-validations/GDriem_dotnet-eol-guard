Paste this into any AI coding assistant (chat or agent) that can read files and run commands:

---
Upgrade this repository off unsupported .NET versions and fix vulnerable NuGet packages.
Follow the playbook in `skills/dotnet-eol-guard/SKILL.md` (and its `references/breaking-changes.md`) step by step:
scan with `scripts/eol-guard.cs`, show me the plan, record a build/test baseline, upgrade in the documented
order, fix build errors, run the tests, re-scan, and report before/after. Ask me before any decision the
playbook marks as needing confirmation. Do not commit or push.
---

Assistants that cannot run commands: run the scanner yourself
(`cd dotnet-eol-guard/skills/dotnet-eol-guard/scripts && dotnet run eol-guard.cs -- --path <repo>`) and paste the report together
with SKILL.md into the chat.
