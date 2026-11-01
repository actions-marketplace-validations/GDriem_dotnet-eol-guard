#!/usr/bin/env python3
"""Generate the Codex custom agents (codex/agents/*.toml) from the Claude Code agents (agents/*.md).

The Markdown files are the single source of truth; run this after editing any of them.
Model tiers map to Codex models; change MODELS if your account uses other model names.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Claude tier -> (Codex model, reasoning effort). Per agent overrides below.
MODELS = {
    "haiku": ("gpt-6-luna", "medium"),
    "sonnet": ("gpt-6.1-sol", "medium"),
    "opus": ("gpt-6.1-sol", "xhigh"),
}
OVERRIDES = {"eol-build-fixer": ("gpt-6.1-sol", "high")}


def toml_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> None:
    out_dir = ROOT / "codex" / "agents"
    out_dir.mkdir(parents=True, exist_ok=True)
    for md in sorted((ROOT / "agents").glob("*.md")):
        text = md.read_text(encoding="utf-8")
        match = re.match(r"^---\n(.*?)\n---\n(.*)$", text, re.S)
        if not match:
            raise SystemExit(f"{md}: missing front matter")
        meta = dict(line.split(": ", 1) for line in match.group(1).splitlines() if ": " in line)
        body = match.group(2).strip()
        name = meta["name"]
        model, effort = OVERRIDES.get(name, MODELS[meta.get("model", "sonnet")])
        # Codex cannot restrict tools per agent; state read-only roles in the instructions instead.
        if "Edit" not in meta.get("tools", ""):
            body = "You are read-only: never create, edit or delete files in the repository.\n\n" + body
        body = body.replace("Claude Code", "Codex")
        # Codex agent names use underscores; keep cross-references consistent.
        body = re.sub(r"\beol-(scanner|upgrader|build-fixer|verifier)\b", lambda m: "eol_" + m.group(1).replace("-", "_"), body)
        toml = "\n".join([
            f"# Generated from agents/{md.name} by tools/gen-codex-agents.py - do not edit by hand.",
            f"name = {toml_string(name.replace('-', '_'))}",
            f"description = {toml_string(re.sub(r'eol-(upgrader|scanner|verifier|build-fixer)', lambda m: 'eol_' + m.group(1).replace('-', '_'), meta['description']))}",
            f"model = {toml_string(model)}",
            f"model_reasoning_effort = {toml_string(effort)}",
            "developer_instructions = '''",
            body,
            "'''",
            "",
        ])
        if "'''" in body:
            raise SystemExit(f"{md}: body contains ''' and cannot be a TOML literal string")
        (out_dir / f"{name}.toml").write_text(toml, encoding="utf-8")
        print(f"codex/agents/{name}.toml  <- {md.name}  ({model}, {effort})")


if __name__ == "__main__":
    main()
