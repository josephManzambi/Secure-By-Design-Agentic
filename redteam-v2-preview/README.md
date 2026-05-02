# Red Team Configuration (v2 — Preview)

> ⚠️ **This folder is not used in v1.** The files here are scaffolding for v2,
> when the [AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator)
> integration is finished and stable.

## Why is this here?

The orchestrator is being actively debugged for inconsistent results across runs.
Until the underlying issues are resolved (PyRIT version pinning, Promptfoo
grader fallbacks, Garak probe drift), the automated pipeline cannot be trusted
to produce reproducible findings.

For v1 of Secure-By-Design-Agentic, we use **manual red-team validation**
instead — see [`docs/MANUAL_REDTEAM.md`](../docs/MANUAL_REDTEAM.md) for the
test cases that have been validated against this codebase.

## What's in this folder

- **`mcp_client_config.json`** — Target descriptor for `mcp-scan` to point at
  the secure MCP server. This works today but is part of the larger v2
  pipeline.
- **`run_redteam.sh`** — Wrapper script that invokes the full orchestrator.
  Will work once the orchestrator is stable.

## When does v2 ship?

v2 ships when the orchestrator produces consistent results across three
consecutive runs against the same target. Tracking issues in the orchestrator
repo: https://github.com/josephManzambi/ai-redteam-orchestrator/issues

## Can I run mcp-scan today?

Yes — mcp-scan is the most stable component of the orchestrator stack and
runs independently. From the project root:

```bash
npx -y mcp-scan@latest scan -c redteam-v2-preview/mcp_client_config.json --json
```

This static analysis of the MCP server's tool descriptors is included in the
v1 manual validation suite.
