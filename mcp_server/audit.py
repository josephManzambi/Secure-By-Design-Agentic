"""
MCP Server Audit
=================
Server-side audit logging for all tool invocations. Separate from the
agent-side audit logger — defense in depth means both sides log.

Framework alignment:
    OWASP MCP Security Guide:
        "Audit everything — every tool invocation, every parameter,
        every result."

    CSA AICM LOG-01:
        Logging and monitoring controls for AI system operations.
"""

from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any


class ServerAuditLog:
    """Append-only server-side audit log."""

    def __init__(self, log_file: str = "mcp_server_audit.jsonl"):
        self.log_file = Path(log_file)

    def log(
        self,
        event: str,
        tool_name: str,
        parameters: dict[str, Any] | None = None,
        result_summary: str = "",
        error: str | None = None,
    ) -> None:
        """Log a server-side audit event."""
        entry = {
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "event": event,
            "tool_name": tool_name,
            "parameter_keys": list(parameters.keys()) if parameters else [],
            "result_length": len(result_summary),
            "success": error is None,
        }
        if error:
            entry["error"] = error[:500]  # Truncate error messages

        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            pass  # Don't let logging failures break tool execution
