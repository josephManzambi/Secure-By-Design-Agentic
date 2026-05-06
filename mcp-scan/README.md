# mcp-scan Configuration

This folder holds the target descriptor used by `mcp-scan` to discover the
secure MCP server in this repo.

- **`mcp_client_config.json`** — Points `mcp-scan` at `mcp_server.server`.
  Used by CI on every push, and by the manual validation suite in
  [`../docs/MANUAL_REDTEAM.md`](../docs/MANUAL_REDTEAM.md).

## Running it locally

From the project root:

```bash
npx -y mcp-scan@latest scan -c mcp-scan/mcp_client_config.json --json
```

This performs static analysis of the MCP server's tool descriptors —
checking for tool poisoning, injection vectors in descriptions, and other
patterns flagged by the OWASP MCP Security Guide.
