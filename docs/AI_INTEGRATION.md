# AI Agent Integration

Lockrail ships a SKILL.md that teaches AI agents (Claude Code, Codex, Cursor, Antigravity)
how to operate safely inside a Lockrail-protected environment.

## Install the skill

```bash
lockrail ai enable               # all supported agents
lockrail ai enable --tool claude # Claude Code only
lockrail ai enable --tool codex  # OpenAI Codex only
lockrail ai enable --tool agy    # Antigravity only
```

## What this does

Copies SKILL.md to each agent's skill directory:
- Claude Code: ~/.claude/
- Codex: ~/.codex/
- Cursor: .cursorrules (project root)
- Antigravity: ~/.agy/skills/

## Install Claude Code hooks (deeper integration)

```bash
lockrail ai hooks --tool claude
```

This writes a UserPromptSubmit hook to ~/.claude/settings.json that pipes
every prompt through lockrail hook prompt before Claude sees it.
