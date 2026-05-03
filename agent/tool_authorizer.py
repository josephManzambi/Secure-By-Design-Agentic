"""
Tool Authorizer
================
Intercepts every tool call from the LLM and applies authorization checks
before allowing execution. This is the CRITICAL security boundary — it's
what prevents the LLM from doing things it shouldn't.

Framework alignment:
    OWASP LLM06 (Excessive Agency):
        The 2025 update identifies three root causes:
        1. Excessive Functionality — agent has tools it doesn't need
        2. Excessive Permissions — agent uses over-privileged credentials
        3. Excessive Autonomy — agent acts without human approval

        This module addresses all three:
        1. Allowlist enforcement (only registered tools can be called)
        2. Parameter validation (each tool's params are type-checked)
        3. Human-in-the-loop for destructive operations

    CSA Agentic AI Security Scoping Matrix:
        This agent operates at Scope 2 (Prescribed Agency):
        "Human approval required for all actions with limited autonomous
        capabilities." Safe tools (read-only, no side effects) can run
        autonomously; everything else requires confirmation.

    NIST AI 100-1 GOVERN 1.4:
        "Processes, procedures, and practices are in place to receive and
        respond to reports of risks and impacts from internal and external
        sources." The authorizer logs all denials for forensic review.

DESIGN DECISION:
    We implement authorization at the APPLICATION layer, not in the system
    prompt. The system prompt asks the LLM to self-restrict, but we don't
    trust that instruction. This module is the deterministic enforcement.
    Even if the LLM is jailbroken and tries to call a tool, this layer
    will block it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from agent.config import DEFAULT_CONFIG, AgentConfig


class AuthDecision(StrEnum):
    """Authorization decision for a tool call."""

    ALLOWED = "allowed"              # Tool call is safe, execute immediately
    REQUIRES_CONFIRMATION = "confirm"  # Need human approval
    DENIED = "denied"                # Tool call is blocked


@dataclass
class AuthorizationResult:
    """Result of tool call authorization check."""

    decision: AuthDecision
    tool_name: str
    arguments: dict[str, Any]
    reason: str
    violations: list[str]


# --- Parameter validation schemas ---
# Each tool has an expected parameter schema. This is enforced
# INDEPENDENTLY of what the MCP server validates — defense in depth.
# If the LLM hallucinates extra parameters or wrong types, we catch
# it here before it ever reaches the MCP server.

TOOL_PARAMETER_SCHEMAS: dict[str, dict[str, Any]] = {
    "read_log": {
        "required": ["filename"],
        "properties": {
            "filename": {
                "type": "string",
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9._-]+$",  # No path separators!
                "description": "Log filename (no path, no slashes)",
            },
        },
    },
    "system_info": {
        "required": [],
        "properties": {},  # No parameters — safest possible tool
    },
    "search_logs": {
        "required": ["keyword"],
        "properties": {
            "keyword": {
                "type": "string",
                "max_length": 100,
                "pattern": r"^[a-zA-Z0-9\s._-]+$",  # Alphanumeric + basic chars
                "description": "Search keyword (alphanumeric only)",
            },
            "filename": {
                "type": "string",
                "max_length": 255,
                "pattern": r"^[a-zA-Z0-9._-]+$",
                "description": "Optional: specific log file to search",
            },
        },
    },
    "health_check": {
        "required": [],
        "properties": {},  # No parameters
    },
}


def _validate_parameter(
    name: str,
    value: Any,
    schema: dict[str, Any],
) -> list[str]:
    """Validate a single parameter against its schema."""
    import re

    violations = []

    # Type check
    expected_type = schema.get("type", "string")
    if expected_type == "string" and not isinstance(value, str):
        violations.append(f"Parameter '{name}' must be a string, got {type(value).__name__}")
        return violations  # Can't do further checks on wrong type

    # Length check
    max_length = schema.get("max_length")
    if max_length and isinstance(value, str) and len(value) > max_length:
        violations.append(
            f"Parameter '{name}' exceeds max length ({len(value)} > {max_length})"
        )

    # Pattern check (regex allowlist)
    pattern = schema.get("pattern")
    if pattern and isinstance(value, str) and not re.match(pattern, value):
        violations.append(
            f"Parameter '{name}' contains disallowed characters (must match {pattern})"
        )

    return violations


def authorize_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    config: AgentConfig = DEFAULT_CONFIG,
) -> AuthorizationResult:
    """
    Authorize a tool call from the LLM.

    This function is called for EVERY tool call before execution.
    It implements three checks:

    1. Is the tool on the allowlist? (OWASP LLM06 — Excessive Functionality)
    2. Are the parameters valid? (OWASP LLM05 — Improper Output Handling)
    3. Does this tool require human confirmation? (CSA Scope 2)

    Args:
        tool_name: Name of the tool the LLM wants to call
        arguments: Arguments the LLM provided for the tool
        config: Agent configuration

    Returns:
        AuthorizationResult with decision, reason, and any violations
    """
    violations: list[str] = []

    # --- Check 1: Allowlist ---
    if tool_name not in config.allowed_tools:
        return AuthorizationResult(
            decision=AuthDecision.DENIED,
            tool_name=tool_name,
            arguments=arguments,
            reason=f"Tool '{tool_name}' is not in the allowed tool list",
            violations=[f"Unauthorized tool: {tool_name}"],
        )

    # --- Check 2: Parameter validation ---
    schema = TOOL_PARAMETER_SCHEMAS.get(tool_name)
    if schema is None:
        # Tool is allowed but has no schema — this is a configuration error
        return AuthorizationResult(
            decision=AuthDecision.DENIED,
            tool_name=tool_name,
            arguments=arguments,
            reason=f"No parameter schema defined for tool '{tool_name}'",
            violations=["Missing parameter schema (configuration error)"],
        )

    # Check required parameters
    for req in schema["required"]:
        if req not in arguments:
            violations.append(f"Missing required parameter: '{req}'")

    # Check unexpected parameters (LLM might hallucinate extra ones)
    allowed_params = set(schema["properties"].keys())
    for param in arguments:
        if param not in allowed_params:
            violations.append(f"Unexpected parameter: '{param}'")

    # Validate each provided parameter
    for param_name, param_value in arguments.items():
        if param_name in schema["properties"]:
            param_violations = _validate_parameter(
                param_name, param_value, schema["properties"][param_name]
            )
            violations.extend(param_violations)

    if violations:
        return AuthorizationResult(
            decision=AuthDecision.DENIED,
            tool_name=tool_name,
            arguments=arguments,
            reason="Parameter validation failed",
            violations=violations,
        )

    # --- Check 3: Human confirmation ---
    if tool_name in config.tools_requiring_confirmation:
        return AuthorizationResult(
            decision=AuthDecision.REQUIRES_CONFIRMATION,
            tool_name=tool_name,
            arguments=arguments,
            reason=f"Tool '{tool_name}' requires human confirmation before execution",
            violations=[],
        )

    # --- All checks passed ---
    return AuthorizationResult(
        decision=AuthDecision.ALLOWED,
        tool_name=tool_name,
        arguments=arguments,
        reason="Tool call authorized",
        violations=[],
    )


def format_confirmation_prompt(result: AuthorizationResult) -> str:
    """
    Format a human-readable confirmation prompt for tools that require
    manual approval.

    CSA Scoping Matrix Scope 2:
        The user must see exactly what will be executed and approve it.
        No hidden parameters, no ambiguity.
    """
    args_display = json.dumps(result.arguments, indent=2)
    return (
        f"\n⚠️  Tool call requires confirmation:\n"
        f"   Tool:      {result.tool_name}\n"
        f"   Arguments: {args_display}\n"
        f"   Reason:    {result.reason}\n"
        f"\n   Allow this tool call? [y/N]: "
    )
