# MCP descriptor scan

This folder holds the MCP descriptor scan that CI runs on every push to `main` and every pull
request. The folder name is historical: it used to hold a config for `npx -y mcp-scan@latest`.
That npm package is not the Invariant Labs scanner the name suggests. The version I tested (2.0.2)
read the client config file, never started the server, and never saw a tool description, so I
removed it. The full account is in [Your Security Scanner Is a Supply Chain Too](https://manzambi.com/writing/your-security-scanner-is-a-supply-chain-too).

- **`mcp_client_config.json`** points the scanner at `mcp_server.server`.
- **`descriptor_scan.py`** runs the descriptor scanner from
  [ai-redteam-orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator) v0.1.0
  against that config and exits 1 on any CRITICAL or HIGH finding, or if the server does not
  start and list its tools.

## What it checks, and what it does not

The scanner starts the server over stdio, reads `tools/list`, and checks each tool's name and
description for hidden instructions, references to secret files, invisible Unicode, secret-shaped
tokens, and wording that advertises command execution. It never calls a tool. It matches keywords,
so a paraphrased instruction can pass, and it says nothing about what a tool does at runtime. Path
traversal and command injection are covered by the manual suite, not by this scan.

## Running it locally

From the project root, the same steps CI runs (macOS: use `shasum -a 256 -c -`):

```bash
uv sync
curl -fsSL -o /tmp/redteam_orchestrator.py \
  https://raw.githubusercontent.com/josephManzambi/ai-redteam-orchestrator/e0c10c7162b124242503060dfa171ed5a8f9174f/redteam_orchestrator.py
echo "cb898dbb542e51823b3c9ac925077b02f827ead14fbf498e7dd5dfc1ce991ff8  /tmp/redteam_orchestrator.py" | sha256sum -c -
uv run python mcp-scan/descriptor_scan.py /tmp/redteam_orchestrator.py \
  mcp-scan/mcp_client_config.json mcp_descriptor_scan.json
```

Expected today: one server, four tools, zero findings, exit code 0.
