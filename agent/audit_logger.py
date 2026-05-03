"""
Audit Logger
=============
Structured, append-only audit logging for all security-relevant events.
Every tool call, authorization decision, input validation result, and
output redaction is recorded.

Framework alignment:
    OWASP LLM09 (Misinformation):
        Audit logs provide a forensic trail to verify what the agent
        actually did vs. what it claimed to do.

    NIST AI 100-1 MEASURE 2.6:
        "Processes are in place to monitor AI system performance and
        behavior over time." Audit logs enable retrospective analysis
        of agent behavior.

    CSA AICM LOG-01:
        "Logging and monitoring controls for AI system operations."

    MCP Security Best Practices (OWASP MCP Guide):
        "Audit everything — every tool invocation, every parameter,
        every result."

DESIGN DECISIONS:
    1. JSONL format — one JSON object per line, easy to parse with
       standard tools (jq, Python, Splunk, etc.)
    2. Append-only — the logger never modifies or deletes entries.
       This is a security requirement — tamper-evident logging.
    3. No sensitive data in logs — we log tool names and parameter
       names, but we redact parameter VALUES for sensitive tools.
       The audit trail shows WHAT happened, not the full payload.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from rich.console import Console

console = Console(stderr=True)


class EventType(StrEnum):
    """Categories of auditable events."""

    INPUT_VALIDATION = "input_validation"
    TOOL_CALL_REQUESTED = "tool_call_requested"
    TOOL_CALL_AUTHORIZED = "tool_call_authorized"
    TOOL_CALL_DENIED = "tool_call_denied"
    TOOL_CALL_CONFIRMED = "tool_call_confirmed"
    TOOL_CALL_REJECTED = "tool_call_rejected"
    TOOL_CALL_EXECUTED = "tool_call_executed"
    TOOL_CALL_FAILED = "tool_call_failed"
    OUTPUT_FILTERED = "output_filtered"
    RATE_LIMIT_HIT = "rate_limit_hit"
    SESSION_START = "session_start"
    SESSION_END = "session_end"


@dataclass
class AuditEvent:
    """A single audit log entry."""

    timestamp: str
    event_type: str
    details: dict[str, Any]
    session_id: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


class AuditLogger:
    """
    Append-only structured audit logger.

    All security-relevant events are logged to a JSONL file.
    The logger also prints a human-readable summary to stderr
    (using Rich) for real-time monitoring during development.
    """

    def __init__(
        self,
        log_file: str = "audit.jsonl",
        session_id: str = "",
        verbose: bool = True,
    ):
        self.log_file = Path(log_file)
        self.session_id = session_id or self._generate_session_id()
        self.verbose = verbose
        self._event_count = 0

        # Log session start
        self.log(EventType.SESSION_START, {"log_file": str(self.log_file)})

    @staticmethod
    def _generate_session_id() -> str:
        """Generate a unique session ID based on timestamp."""
        return datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")

    def _now(self) -> str:
        return datetime.datetime.now(datetime.UTC).isoformat()

    def log(self, event_type: EventType, details: dict[str, Any]) -> None:
        """
        Log an audit event.

        Args:
            event_type: Category of the event
            details: Event-specific data (will be serialized to JSON)
        """
        event = AuditEvent(
            timestamp=self._now(),
            event_type=event_type.value,
            details=details,
            session_id=self.session_id,
        )
        self._event_count += 1

        # Write to JSONL file (append-only)
        try:
            with open(self.log_file, "a") as f:
                f.write(event.to_json() + "\n")
        except OSError as e:
            console.print(f"[red]Audit log write failed: {e}[/red]", highlight=False)

        # Print to stderr for real-time monitoring
        if self.verbose:
            self._print_event(event)

    def _print_event(self, event: AuditEvent) -> None:
        """Print a human-readable audit event to stderr."""
        style_map = {
            EventType.TOOL_CALL_DENIED.value: "bold red",
            EventType.TOOL_CALL_REJECTED.value: "bold red",
            EventType.TOOL_CALL_FAILED.value: "red",
            EventType.OUTPUT_FILTERED.value: "yellow",
            EventType.RATE_LIMIT_HIT.value: "bold yellow",
            EventType.INPUT_VALIDATION.value: "cyan",
            EventType.TOOL_CALL_AUTHORIZED.value: "green",
            EventType.TOOL_CALL_EXECUTED.value: "green",
        }
        style = style_map.get(event.event_type, "dim")
        console.print(
            f"  [{style}]AUDIT[/{style}] {event.event_type}: "
            f"{json.dumps(event.details, default=str)}",
            highlight=False,
        )

    def log_input_validation(
        self,
        risk_level: str,
        flags: list[str],
        input_length: int,
    ) -> None:
        """Log an input validation event (OWASP LLM01)."""
        self.log(
            EventType.INPUT_VALIDATION,
            {
                "risk_level": risk_level,
                "flags": flags,
                "input_length": input_length,
                # NOTE: We do NOT log the actual input content.
                # The audit trail shows risk classification, not payload.
            },
        )

    def log_tool_request(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> None:
        """Log that the LLM requested a tool call."""
        # Redact parameter values for sensitive tools
        safe_args = {k: "***" for k in arguments}
        self.log(
            EventType.TOOL_CALL_REQUESTED,
            {
                "tool_name": tool_name,
                "argument_keys": list(arguments.keys()),
                "arguments_redacted": safe_args,
            },
        )

    def log_tool_authorized(self, tool_name: str, decision: str, reason: str) -> None:
        """Log authorization decision (OWASP LLM06)."""
        event_type = {
            "allowed": EventType.TOOL_CALL_AUTHORIZED,
            "confirm": EventType.TOOL_CALL_AUTHORIZED,
            "denied": EventType.TOOL_CALL_DENIED,
        }.get(decision, EventType.TOOL_CALL_DENIED)

        self.log(event_type, {"tool_name": tool_name, "decision": decision, "reason": reason})

    def log_tool_execution(
        self,
        tool_name: str,
        success: bool,
        duration_ms: float,
        error: str | None = None,
    ) -> None:
        """Log tool execution result."""
        event_type = EventType.TOOL_CALL_EXECUTED if success else EventType.TOOL_CALL_FAILED
        details: dict[str, Any] = {
            "tool_name": tool_name,
            "success": success,
            "duration_ms": round(duration_ms, 2),
        }
        if error:
            details["error"] = error
        self.log(event_type, details)

    def log_output_filtered(self, redactions: list[str]) -> None:
        """Log output filtering actions (OWASP LLM02, LLM05)."""
        if redactions:
            self.log(EventType.OUTPUT_FILTERED, {"redactions": redactions})

    def close(self) -> None:
        """Log session end."""
        self.log(
            EventType.SESSION_END,
            {"total_events": self._event_count},
        )
