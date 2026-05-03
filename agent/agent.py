"""
Secure Agent
=============
Main agent loop that orchestrates all security layers: input validation,
LLM interaction, tool authorization, tool execution, and output filtering.

This is deliberately built WITHOUT a framework (no LangChain, no CrewAI,
no LlamaIndex). Every security boundary is visible and auditable.

Framework alignment:
    NIST AI 100-1 GOVERN 1.1:
        "The organization has identified and documented the AI system's
        intended purpose, potential risks, and the context of its use."
        This agent has a single, well-defined purpose (system diagnostics)
        with explicitly documented constraints.

    CSA Agentic AI Security Scoping Matrix — Scope 2 (Prescribed Agency):
        "Human-initiated, human approval required for all actions with
        limited autonomous capabilities." Safe tools run automatically;
        sensitive tools require human confirmation.

    OWASP LLM06 (Excessive Agency):
        Defense-in-depth: system prompt constraints (soft) + tool
        authorizer enforcement (hard) + output filtering (last resort).

Usage:
    uv run python -m agent.agent
"""

from __future__ import annotations

import json
import time
from typing import Any

from rich.console import Console
from rich.panel import Panel

from agent.audit_logger import AuditLogger, EventType
from agent.config import DEFAULT_CONFIG, AgentConfig
from agent.input_guard import RiskLevel, validate_input
from agent.output_filter import filter_output
from agent.tool_authorizer import (
    AuthDecision,
    authorize_tool_call,
    format_confirmation_prompt,
)

console = Console()


# --- Tool definitions for the LLM ---
# These are the tool descriptions sent to the model. They must match
# the tools actually available on the MCP server.
#
# OWASP MCP Security Guide:
#   "Treat MCP tool docstrings as untrusted; review each @mcp.tool()
#   description shown to the model."
#   Our descriptions are minimal and factual — no hidden instructions.

TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": "read_log",
            "description": (
                "Read the contents of a log file from the log directory. "
                "Only filenames are accepted (no paths)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "Name of the log file to read (e.g., 'syslog', 'auth.log')",
                    },
                },
                "required": ["filename"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "system_info",
            "description": (
                "Get current system information including hostname, OS, and uptime. "
                "Takes no parameters."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_logs",
            "description": "Search for a keyword in log files. Returns matching lines.",
            "parameters": {
                "type": "object",
                "properties": {
                    "keyword": {
                        "type": "string",
                        "description": "The keyword to search for (alphanumeric characters only)",
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional: specific log file to search in",
                    },
                },
                "required": ["keyword"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "health_check",
            "description": "Check the health status of the system. Takes no parameters.",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]


def _execute_tool(tool_name: str, arguments: dict[str, Any]) -> str:
    """
    Execute a tool call against the MCP server.

    In a full deployment, this would communicate with the MCP server
    over the MCP protocol. For this educational implementation, we
    import the server functions directly to keep the setup simple.

    The security boundary is STILL enforced by tool_authorizer.py —
    this function is only called after authorization passes.
    """
    try:
        from mcp_server.server import health_check, read_log, search_logs, system_info

        tool_map = {
            "read_log": read_log,
            "system_info": system_info,
            "search_logs": search_logs,
            "health_check": health_check,
        }

        func = tool_map.get(tool_name)
        if func is None:
            return f"Error: Unknown tool '{tool_name}'"

        return func(**arguments)
    except Exception as e:
        return f"Error executing {tool_name}: {e!r}"


def _request_human_confirmation(prompt: str) -> bool:
    """
    Ask the user for confirmation before executing a sensitive tool.

    CSA Scoping Matrix Scope 2:
        Human approval is required. The prompt shows exactly what
        will be executed — no hidden parameters.
    """
    console.print(prompt, highlight=False)
    try:
        response = input().strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        return False


def run_agent(config: AgentConfig = DEFAULT_CONFIG) -> None:
    """
    Main agent loop.

    Flow for each user turn:
    1. Read user input
    2. Validate input (input_guard.py)
    3. Send to LLM with tool definitions
    4. If LLM requests tool call:
       a. Authorize the call (tool_authorizer.py)
       b. If requires confirmation, ask user
       c. Execute the tool
       d. Send result back to LLM
    5. Filter LLM response (output_filter.py)
    6. Display to user
    7. Log everything (audit_logger.py)
    """
    logger = AuditLogger(log_file=config.audit_log_file, verbose=True)

    console.print(Panel(
        "[bold]Secure Agent[/bold] — System Diagnostics Assistant\n\n"
        f"Model: {config.model_name}\n"
        f"Allowed tools: {', '.join(config.allowed_tools)}\n"
        f"Tools requiring confirmation: {', '.join(config.tools_requiring_confirmation)}\n\n"
        "[dim]Type 'quit' or 'exit' to end the session.[/dim]",
        title="🛡️ Secure-By-Design Agent",
        style="green",
    ))

    messages = [{"role": "system", "content": config.system_prompt}]
    turn_count = 0

    try:
        import ollama as ollama_sdk
    except ImportError:
        console.print("[red]Error: ollama package not installed. Run: uv add ollama[/red]")
        return

    while turn_count < config.max_conversation_turns:
        # --- Step 1: Read input ---
        try:
            user_input = input("\n🧑 You: ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if user_input.lower() in ("quit", "exit", "q"):
            break

        if not user_input:
            continue

        turn_count += 1

        # --- Step 2: Validate input ---
        analysis = validate_input(user_input, max_length=config.max_input_length)
        logger.log_input_validation(
            risk_level=analysis.risk_level.value,
            flags=analysis.flags,
            input_length=len(user_input),
        )

        if not analysis.is_allowed:
            console.print(
                f"\n[red]⛔ Input blocked:[/red] {'; '.join(analysis.flags)}",
                highlight=False,
            )
            continue

        if analysis.risk_level == RiskLevel.SUSPICIOUS:
            console.print(
                f"\n[yellow]⚠️  Suspicious input flagged:[/yellow] {'; '.join(analysis.flags)}",
                highlight=False,
            )
            # We still process suspicious inputs — the flags are informational.
            # The real security boundaries are downstream (tool authorizer, output filter).

        # --- Step 3: Send to LLM ---
        messages.append({"role": "user", "content": analysis.sanitized_input})

        try:
            response = ollama_sdk.chat(
                model=config.model_name,
                messages=messages,
                tools=TOOL_DEFINITIONS,
            )
        except Exception as e:
            console.print(f"\n[red]LLM error: {e!r}[/red]")
            messages.pop()  # Remove the failed user message
            continue

        # --- Step 4: Handle tool calls ---
        tool_calls_this_turn = 0
        while response.message.tool_calls and tool_calls_this_turn < config.max_tool_calls_per_turn:
            for tool_call in response.message.tool_calls:
                tool_calls_this_turn += 1
                tool_name = tool_call.function.name
                arguments = tool_call.function.arguments or {}

                # Log the request
                logger.log_tool_request(tool_name, arguments)

                # --- Step 4a: Authorize ---
                auth_result = authorize_tool_call(tool_name, arguments, config)
                logger.log_tool_authorized(
                    tool_name, auth_result.decision.value, auth_result.reason
                )

                if auth_result.decision == AuthDecision.DENIED:
                    console.print(
                        f"\n[red]⛔ Tool call denied:[/red] {auth_result.reason}",
                        highlight=False,
                    )
                    if auth_result.violations:
                        for v in auth_result.violations:
                            console.print(f"   • {v}", highlight=False)

                    # Tell the LLM the tool call was denied
                    messages.append(response.message)
                    messages.append({
                        "role": "tool",
                        "content": (
                            f"DENIED: {auth_result.reason}. "
                            f"Violations: {auth_result.violations}"
                        ),
                    })
                    break

                # --- Step 4b: Human confirmation ---
                if auth_result.decision == AuthDecision.REQUIRES_CONFIRMATION:
                    prompt = format_confirmation_prompt(auth_result)
                    if not _request_human_confirmation(prompt):
                        console.print("[yellow]Tool call rejected by user.[/yellow]")
                        logger.log(EventType.TOOL_CALL_REJECTED, {"tool_name": tool_name})
                        messages.append(response.message)
                        messages.append({
                            "role": "tool",
                            "content": "Tool call was rejected by the user.",
                        })
                        break

                # --- Step 4c: Execute ---
                console.print(
                    f"\n[green]✅ Executing:[/green] {tool_name}({json.dumps(arguments)})",
                    highlight=False,
                )

                start_time = time.monotonic()
                result = _execute_tool(tool_name, arguments)
                duration_ms = (time.monotonic() - start_time) * 1000

                logger.log_tool_execution(
                    tool_name=tool_name,
                    success=not result.startswith("Error"),
                    duration_ms=duration_ms,
                    error=result if result.startswith("Error") else None,
                )

                # Add tool result to conversation
                messages.append(response.message)
                messages.append({"role": "tool", "content": result})

            # Get next LLM response (it may request more tools)
            if tool_calls_this_turn < config.max_tool_calls_per_turn:
                try:
                    response = ollama_sdk.chat(
                        model=config.model_name,
                        messages=messages,
                        tools=TOOL_DEFINITIONS,
                    )
                except Exception as e:
                    console.print(f"\n[red]LLM error during tool loop: {e!r}[/red]")
                    break
            else:
                console.print(
                    "\n[yellow]⚠️  Max tool calls per turn reached "
                    f"({config.max_tool_calls_per_turn})[/yellow]"
                )
                break

        # --- Step 5: Filter output ---
        raw_response = response.message.content or ""
        filter_result = filter_output(raw_response)
        logger.log_output_filtered(filter_result.redactions)

        if filter_result.was_modified:
            console.print(
                f"\n[yellow]⚠️  Output filtered: "
                f"{len(filter_result.redactions)} redaction(s)[/yellow]",
                highlight=False,
            )

        # --- Step 6: Display to user ---
        console.print(f"\n🤖 Agent: {filter_result.filtered_text}")

        # Add assistant message to conversation history
        messages.append({"role": "assistant", "content": filter_result.filtered_text})

    # --- Session end ---
    logger.close()
    console.print(f"\n[dim]Session ended. Audit log saved to {config.audit_log_file}[/dim]")


if __name__ == "__main__":
    run_agent()
