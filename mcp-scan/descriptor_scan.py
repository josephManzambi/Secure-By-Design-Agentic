"""Scan this repo's MCP server with the descriptor scanner from ai-redteam-orchestrator.

The scanner starts the server over stdio, reads what `tools/list` returns, and
checks each tool's name and description against keyword heuristics (hidden
instructions, secret paths, invisible Unicode, secret-shaped tokens, execution
wording). It is static: it never calls a tool.

Usage:
    uv run python mcp-scan/descriptor_scan.py ORCHESTRATOR_PY CLIENT_CONFIG OUT_JSON

Exits 1 if the scan script fails or prints no JSON, if a server fails to start
or list tools, if no tools are found, or if any finding is CRITICAL or HIGH.
On a failure it prints the scan script's stderr, which includes the server's.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    orchestrator, config, out = sys.argv[1:4]
    spec = importlib.util.spec_from_file_location("rto", orchestrator)
    rto = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rto)

    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / "mcp_descriptor_scan.py"
        script.write_text(rto._mcp_descriptor_scan_script())
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, str(script), config],
            capture_output=True, text=True, timeout=120, check=False,
        )
    raw = proc.stdout
    if proc.returncode != 0 or "{" not in raw:
        print(
            f"descriptor scan: scan script exited {proc.returncode} "
            f"or printed no JSON. stderr follows:\n{proc.stderr}",
            file=sys.stderr,
        )
        return 1
    servers = json.loads(raw[raw.find("{"):])["servers"]
    report = rto.analyze_tool_descriptors(servers)
    Path(out).write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))

    failed = [s["name"] for s in servers if s.get("status") != "ok"]
    if failed or report["totalTools"] == 0:
        errors = {s["name"]: s.get("error") for s in servers if s.get("status") != "ok"}
        print(
            f"descriptor scan: server(s) did not list tools: {failed}\n"
            f"errors: {errors}\nstderr follows:\n{proc.stderr}",
            file=sys.stderr,
        )
        return 1
    if report["criticalCount"] or report["highCount"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
