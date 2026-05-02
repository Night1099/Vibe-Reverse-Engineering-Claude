# Cost Routing via free-claude-code Proxy

The main agent runs on Opus. Every subagent runs on **DeepSeek V4 Flash** via the [free-claude-code](https://github.com/Alishahryar1/free-claude-code) proxy. This document is the operator's setup guide.

## Architecture

```
Claude Code CLI
  └─ ANTHROPIC_BASE_URL=http://localhost:8082
       └─ free-claude-code proxy
            ├─ opus tier   → Anthropic API (passthrough, real Opus 4.7)
            ├─ sonnet tier → DeepSeek V4 Flash
            └─ haiku tier  → DeepSeek V4 Flash
```

The proxy routes by the model tier in the request:
- Main agent issues requests as `claude-opus-4-7` → proxy forwards untouched.
- Subagents are tagged `model: haiku` (in `.claude/agents/*.md` frontmatter, or via the Agent tool's `model` parameter for built-ins) → proxy rewrites to V4 Flash.

`haiku` is a routing label, not Anthropic Claude Haiku. The proxy never calls Anthropic for haiku/sonnet tiers.

## One-Time Setup

1. Clone and install the proxy:
   ```bash
   git clone https://github.com/Alishahryar1/free-claude-code.git
   cd free-claude-code
   uv sync
   ```

2. Get a DeepSeek API key from https://platform.deepseek.com.

3. Create `.env` in the proxy repo:
   ```env
   # Opus → real Anthropic
   ANTHROPIC_OPUS_PROVIDER=anthropic
   ANTHROPIC_API_KEY=sk-ant-...

   # Sonnet → DeepSeek V4 Flash (catches anything not explicitly haiku)
   ANTHROPIC_SONNET_PROVIDER=deepseek
   # Haiku → DeepSeek V4 Flash (default subagent tier)
   ANTHROPIC_HAIKU_PROVIDER=deepseek

   DEEPSEEK_API_KEY=sk-...
   DEEPSEEK_MODEL=deepseek-v4-flash

   # Fallback for any unrecognized model
   ANTHROPIC_FALLBACK_PROVIDER=deepseek
   ```

4. Start the proxy:
   ```bash
   uv run uvicorn server:app --host 127.0.0.1 --port 8082
   ```

5. In your Claude Code shell, point the CLI at the proxy:
   ```bash
   export ANTHROPIC_BASE_URL=http://localhost:8082
   ```
   Add to your shell profile to persist.

## Verifying

After starting Claude Code with `ANTHROPIC_BASE_URL` set:
- Watch the proxy's stdout. Every main-agent turn should hit the `opus` route.
- Spawn any subagent (e.g. `static-analyzer`). The proxy should log a `haiku` route forwarded to DeepSeek.
- If subagent calls hit `opus` instead, the agent file is missing `model: haiku` or the Agent invocation didn't pass the `model` param — fix the caller.

## Pricing Reference (April 2026)

| Tier | Model | Input ($/M) | Output ($/M) |
|------|-------|-------------|--------------|
| opus | Claude Opus 4.7 | 15.00 | 75.00 |
| haiku/sonnet | DeepSeek V4 Flash | 0.14 | 0.28 |

Cache hits on V4 Flash drop input to $0.014/M. Subagents that re-read the same `kb.h` and `findings.md` benefit heavily from caching.

## Built-in Agents

Project files only exist for `static-analyzer` and `web-researcher`. Built-in agents (`Explore`, `general-purpose`, `Plan`, `claude-code-guide`) inherit the parent's model unless the Agent tool call passes a `model` parameter. The main agent **must** pass `model: "haiku"` on every Agent invocation, built-in or not. This is enforced by the rule in `.claude/CLAUDE.md`, not by config.

## Operational Notes

- DeepSeek V4 Flash has 1M context, so passing whole `findings.md` files to subagents is fine.
- If the proxy is down, the CLI fails closed — start it before invoking Claude Code.
- The proxy is local-only; do not expose port 8082 externally.
- API keys live only in the proxy's `.env`. Never put `DEEPSEEK_API_KEY` in this repo's environment.
