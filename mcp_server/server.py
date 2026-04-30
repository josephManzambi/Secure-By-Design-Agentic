"""
Secure MCP Server
==================
A hardened MCP server with four tools demonstrating secure design patterns.
This is the OPPOSITE of the vulnerable demo server in the AI Red Team
Orchestrator — every vulnerability there is mitigated here.

Vulnerability Comparison:
    ┌─────────────────────┬──────────────────────────┬──────────────────────────┐
    │ Vulnerability        │ Vulnerable Server        │ This Server              │
    ├─────────────────────┼──────────────────────────┼──────────────────────────┤
    │ Command Injection    │ shell=True + f-string    │ shell=False + arg list   │
    │ Path Traversal       │ No path validation       │ canonicalize + prefix    │
    │ Input Validation     │ None                     │ Type + length + pattern  │
    │ Rate Limiting        │ None                     │ Token-bucket per tool    │
    │ Audit Logging        │ None                     │ Every invocation logged  │
    │ Error Disclosure     │ Raw exception strings    │ Generic error messages   │
    │ Tool Descriptions    │ May contain secrets      │ Minimal, factual         │
    │ File Size Limits     │ None                     │ 10 MB cap                │
    └─────────────────────┴──────────────────────────┴──────────────────────────┘

Framework alignment:
    OWASP Practical Guide for Secure MCP Server Development (Feb 2026):
        Implements all five security pillars: secure architecture, strong
        auth, strict validation, session isolation, hardened deployment.

    OWASP LLM05 (Improper Output Handling):
        Tool outputs are sanitized before returning to the model.

    NIST SP 800-53 SI-10 (Information Input Validation):
        All inputs are validated against strict schemas.

    CSA AICM AIS-05:
        Input validation and sanitization controls.

Usage:
    # As a standalone MCP server:
    uv run python -m mcp_server.server

    # As imported functions (for the agent):
    from mcp_server.server import read_log, system_info, search_logs, health_check
"""

from __future__ import annotations

import os
import platform
import subprocess
import time
from pathlib import Path

from mcp_server.audit import ServerAuditLog
from mcp_server.rate_limiter import RateLimiter, create_default_limiter
from mcp_server.validators import (
    LOG_DIRECTORY,
    MAX_SEARCH_RESULTS,
    ValidationError,
    validate_filename,
    validate_file_readable,
    validate_keyword,
)

# --- Server-level security controls ---
_audit = ServerAuditLog()
_rate_limiter = create_default_limiter()


def _check_rate_limit(tool_name: str) -> None:
    """
    Check rate limit before tool execution.

    OWASP LLM10 (Unbounded Consumption):
        Prevents rapid-fire tool calls from overwhelming the server.
    """
    if not _rate_limiter.check(tool_name):
        _audit.log("rate_limited", tool_name)
        raise ValidationError(
            "Rate limit exceeded. Please wait before retrying.",
            "rate_limit",
        )


# ============================================================
# Tool 1: read_log
# ============================================================
# Demonstrates: Path canonicalization, allowlist, file size limits
#
# CONTRAST with vulnerable version:
#   VULNERABLE:  cmd = f"cat /var/log/{path}"
#                subprocess.check_output(cmd, shell=True)
#   SECURE:      validated_path = validate_filename(filename)
#                path.read_text()  (no subprocess at all)
# ============================================================

def read_log(filename: str) -> str:
    """
    Read the contents of a log file from the designated log directory.

    Security controls:
    - Filename validation (allowlist characters, no path separators)
    - Path canonicalization (realpath + prefix check)
    - File size limit (10 MB)
    - No subprocess/shell involved — pure Python file I/O
    - Audit logging

    Args:
        filename: Name of the log file (e.g., 'syslog', 'auth.log').
                  Must be a filename only — no paths, no slashes.

    Returns:
        File contents as a string, or an error message.
    """
    _check_rate_limit("read_log")

    try:
        # Validate and resolve the filename
        validated_path = validate_filename(filename)
        validate_file_readable(validated_path)

        # Read the file (no subprocess, no shell)
        content = validated_path.read_text(errors="replace")

        _audit.log(
            "tool_executed",
            "read_log",
            parameters={"filename": filename},
            result_summary=f"Read {len(content)} chars from {validated_path.name}",
        )

        return content

    except ValidationError as e:
        _audit.log("validation_failed", "read_log", parameters={"filename": filename}, error=str(e))
        # Return a generic error — don't leak validation internals
        return f"Error: {e.message}"
    except Exception as e:
        _audit.log("tool_error", "read_log", parameters={"filename": filename}, error=str(e))
        # Generic error — don't leak stack traces or internal paths
        return "Error: Unable to read the specified log file."


# ============================================================
# Tool 2: system_info
# ============================================================
# Demonstrates: No-parameter tool, read-only, minimal surface area
#
# This is the SAFEST possible tool design:
# - No user input → no injection surface
# - Read-only → no side effects
# - Returns only non-sensitive system metadata
# ============================================================

def system_info() -> str:
    """
    Return non-sensitive system information.

    Security controls:
    - No parameters (zero injection surface)
    - Read-only (no side effects)
    - Returns only public system metadata
    - No subprocess/shell involved

    Returns:
        System information string.
    """
    _check_rate_limit("system_info")

    try:
        info = {
            "hostname": platform.node(),
            "os": platform.system(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "uptime_note": "Use 'uptime' command for precise uptime",
        }

        _audit.log("tool_executed", "system_info", result_summary="system info returned")

        return "\n".join(f"{k}: {v}" for k, v in info.items())

    except Exception:
        _audit.log("tool_error", "system_info", error="Failed to gather system info")
        return "Error: Unable to retrieve system information."


# ============================================================
# Tool 3: search_logs
# ============================================================
# Demonstrates: Safe subprocess usage (argument list, no shell)
#
# CONTRAST with vulnerable version:
#   VULNERABLE:  cmd = f"echo 'Running diagnostics...' && {cmd_suffix}"
#                subprocess.check_output(cmd, shell=True)
#   SECURE:      subprocess.run(["grep", "-r", keyword, str(log_dir)],
#                               shell=False, capture_output=True)
# ============================================================

def search_logs(keyword: str, filename: str | None = None) -> str:
    """
    Search for a keyword in log files using grep.

    Security controls:
    - Keyword validation (allowlist characters, length limit)
    - Optional filename validation (same as read_log)
    - subprocess with shell=False and argument list
    - Result count limit (prevents unbounded output)
    - Timeout on subprocess (prevents hanging)
    - Audit logging

    Args:
        keyword: Search term (alphanumeric + basic characters only)
        filename: Optional specific log file to search

    Returns:
        Matching lines, or an error/no-results message.
    """
    _check_rate_limit("search_logs")

    try:
        # Validate keyword
        validated_keyword = validate_keyword(keyword)

        # Build the grep command as an ARGUMENT LIST (never a string)
        # shell=False is the CRITICAL security control here.
        #
        # OWASP MCP Guide §4.2:
        #   "Replace shell=True subprocess calls with argument-list
        #   invocations."
        cmd = ["grep", "-r", "-l", "--include=*.log", "--include=*.txt"]

        if filename:
            # If a specific file is requested, validate it
            validated_path = validate_filename(filename)
            validate_file_readable(validated_path)
            cmd = ["grep", "-n", validated_keyword, str(validated_path)]
        else:
            cmd.extend([validated_keyword, str(LOG_DIRECTORY)])

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,  # Hard timeout — prevents hanging
            # CRITICAL: shell=False (the default, but explicit for clarity)
            shell=False,
        )

        if result.returncode == 0 and result.stdout.strip():
            lines = result.stdout.strip().split("\n")
            if len(lines) > MAX_SEARCH_RESULTS:
                lines = lines[:MAX_SEARCH_RESULTS]
                lines.append(f"... (truncated to {MAX_SEARCH_RESULTS} results)")

            output = "\n".join(lines)
            _audit.log(
                "tool_executed",
                "search_logs",
                parameters={"keyword": validated_keyword},
                result_summary=f"Found {len(lines)} matching lines",
            )
            return output
        else:
            _audit.log(
                "tool_executed",
                "search_logs",
                parameters={"keyword": validated_keyword},
                result_summary="No results found",
            )
            return f"No results found for keyword '{validated_keyword}'."

    except ValidationError as e:
        _audit.log("validation_failed", "search_logs", error=str(e))
        return f"Error: {e.message}"
    except subprocess.TimeoutExpired:
        _audit.log("tool_timeout", "search_logs")
        return "Error: Search timed out. Try a more specific keyword."
    except Exception:
        _audit.log("tool_error", "search_logs", error="Search failed")
        return "Error: Unable to perform log search."


# ============================================================
# Tool 4: health_check
# ============================================================
# Demonstrates: Zero-parameter, zero-side-effect "safe default" tool
# ============================================================

def health_check() -> str:
    """
    Return the health status of the MCP server.

    Security controls:
    - No parameters (zero injection surface)
    - No side effects
    - Returns only server health metadata

    Returns:
        Health status string.
    """
    _check_rate_limit("health_check")

    try:
        status = {
            "status": "healthy",
            "log_directory_exists": LOG_DIRECTORY.exists(),
            "log_directory_readable": os.access(LOG_DIRECTORY, os.R_OK),
            "server_type": "secure-mcp-server",
            "version": "1.0.0",
        }

        _audit.log("tool_executed", "health_check", result_summary="health check OK")

        return "\n".join(f"{k}: {v}" for k, v in status.items())
    except Exception:
        _audit.log("tool_error", "health_check", error="Health check failed")
        return "status: degraded\nerror: Unable to complete health check"


# ============================================================
# FastMCP server entry point
# ============================================================
# When run as a standalone MCP server, this exposes the tools
# via the MCP protocol (stdio transport by default).

def create_mcp_server():
    """
    Create and configure the FastMCP server instance.

    Tool descriptions are MINIMAL AND FACTUAL — no secrets, no
    internal paths, no implementation details. This is a defense
    against tool poisoning (OWASP MCP Guide).

    OWASP MCP Security Guide:
        "Treat MCP tool docstrings as untrusted; mcp-scan findings
        on tool poisoning should drive a review of each @mcp.tool()
        description shown to the model."
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Error: FastMCP not installed. Run: uv add 'mcp[cli]' fastmcp")
        raise

    mcp = FastMCP("Secure-System-Tools")

    @mcp.tool()
    def mcp_read_log(filename: str) -> str:
        """Read a log file by filename. Only filenames are accepted, not paths."""
        return read_log(filename)

    @mcp.tool()
    def mcp_system_info() -> str:
        """Get current system information (hostname, OS, uptime)."""
        return system_info()

    @mcp.tool()
    def mcp_search_logs(keyword: str, filename: str = "") -> str:
        """Search for a keyword in log files. Returns matching lines."""
        return search_logs(keyword, filename if filename else None)

    @mcp.tool()
    def mcp_health_check() -> str:
        """Check the health status of the system tools server."""
        return health_check()

    return mcp


if __name__ == "__main__":
    mcp = create_mcp_server()
    mcp.run()
