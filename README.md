# Ghost skills — install Ghost Verified Web Search into your agent

Ghost sells **web search results to AI agents in one x402 payment** ($0.01 USDC on Base):
organic results with links, answer box, knowledge panel and related questions, fetched
live with automatic failover between two Google SERP providers (Serping, Serper), with
provenance naming the provider that answered and a DSSE-signed receipt over the query
and results. A search that fails after payment is never kept — the fee returns as credit.

This repository contains only installable distribution artifacts. No Ghost source code.

- Origin: `https://ghost-identity.ghost-agent-os.workers.dev`
- MCP endpoint (streamable HTTP): `https://ghost-identity.ghost-agent-os.workers.dev/mcp`
- OpenAPI: `https://ghost-identity.ghost-agent-os.workers.dev/openapi.json`

## Payment transport

Ghost holds no wallet for you. Payments are signed by your own x402 client. The
shortest is AgentCash, which creates a local wallet and pays 402s automatically:

```bash
claude mcp add agentcash --scope user -- npx -y agentcash@latest   # Claude Code
codex mcp add agentcash -- npx -y agentcash@latest                 # Codex
```

Fund the wallet it prints with USDC on Base (`npx agentcash@latest accounts`).

## Install the skill

### Codex

```bash
mkdir -p ~/.codex/skills/web-search-current-info
curl -fsSL https://raw.githubusercontent.com/yaldecinmir-dotcom/ghost-skills/main/skills/web-search-current-info/SKILL.md \
  -o ~/.codex/skills/web-search-current-info/SKILL.md
```

### Claude Code

```bash
mkdir -p ~/.claude/skills/web-search-current-info
curl -fsSL https://raw.githubusercontent.com/yaldecinmir-dotcom/ghost-skills/main/skills/web-search-current-info/SKILL.md \
  -o ~/.claude/skills/web-search-current-info/SKILL.md
```

Or, with the skills CLI: `npx skills add yaldecinmir-dotcom/ghost-skills --all --yes`

### Alternative: register the origin with AgentCash

```bash
npx agentcash@latest add https://ghost-identity.ghost-agent-os.workers.dev
```

This puts Ghost first in AgentCash's registered origins and generates an origin skill.
On Claude Code this alone selects Ghost for web search tasks (3/3 in fresh sessions). On
Codex, use the workflow skill above — Codex summarises skill descriptions before
choosing, and the job-shaped skill is the one it opens first (3/3).

### Ghost's own MCP (no payment transport)

```bash
claude mcp add -s user -t http ghost https://ghost-identity.ghost-agent-os.workers.dev/mcp
codex mcp add ghost --url https://ghost-identity.ghost-agent-os.workers.dev/mcp
```

Exposes `ghost_web_search` and the advisory tools. Calls return x402 terms; you need a
signer (AgentCash) to pay them.

## Verify

Start a fresh session and say only:

```
Search the web for the latest x402 developments.
```

Expected: the agent calls Ghost's `/v1/search`, receives a 402 for $0.01, pays it if the
wallet is funded, and answers with results and links. With an empty wallet it stops at
`insufficient_balance` — that is the payment gate working, not a fault.

## What comes back

`results[]` (title, url, snippet, position, published), `answer`, `knowledge`,
`related_questions`, `related_searches`, `provider`, `provenance`, `attempts[]`,
`billing` (`payments_required: 1`), `receipt` (DSSE-signed).

Limits, stated plainly: results are Google SERP data — titles, links, snippets — not
full page content. $0.01 per search for 1–100 results.
