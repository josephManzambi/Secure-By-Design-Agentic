# Architecture Decisions

This document explains the WHY behind every architectural choice in
Secure-By-Design-Agentic. Each decision is linked to a specific security
requirement from OWASP, NIST, or CSA.

## Decision 1: No Agent Framework

**Choice:** Build the agent loop from scratch in vanilla Python.

**Alternatives considered:** LangChain, CrewAI, LlamaIndex, Semantic Kernel.

**Rationale:**
Agent frameworks abstract away the exact control surfaces we're trying to
secure. When you call `agent.run()` in LangChain, you don't see:
- How tool calls are dispatched
- What validation happens on parameters
- Whether human confirmation is possible
- What gets logged

For SECURITY EDUCATION, every decision point must be visible and auditable.
NIST AI 100-1 GOVERN 1.1 requires understanding of the system's full attack
surface — you can't understand what you can't see.

For PRODUCTION, a framework is fine as long as you've verified it implements
the security controls you need. This project teaches you what to look for.

## Decision 2: Local Inference Only (Ollama)

**Choice:** Use Ollama for fully local inference. No API keys.

**Alternatives considered:** OpenAI API, Anthropic API, Azure OpenAI.

**Rationale:**
1. **Red-team control:** You can't fully test a model you don't control.
   API providers may have guardrails that mask vulnerabilities in your
   application logic. Local inference lets you test your defenses in
   isolation.
2. **No data exfiltration:** User prompts and tool outputs never leave
   the machine. Essential for security testing with sensitive scenarios.
3. **Reproducibility:** Same model weights, same behavior. API models
   get updated silently.
4. **No cost:** Unlimited testing without API bills.

**Trade-off:** Smaller models (7B) are less capable than frontier models.
This is acceptable for security testing — if your defenses hold against
a model that's MORE susceptible to jailbreaks, they'll hold against
better models too.

## Decision 3: Defense-in-Depth Architecture

**Choice:** Four independent security layers, each operating independently.

**Rationale:**
No single layer is sufficient:
- **Input Guard alone:** Can't catch all prompt injection (OWASP LLM01
  explicitly states this is impossible).
- **System prompt alone:** Stochastic, not deterministic. OWASP LLM07
  says system prompts are not security controls.
- **Tool authorizer alone:** Doesn't help if the model leaks sensitive
  data without calling any tools.
- **Output filter alone:** Doesn't prevent the model from taking
  unauthorized actions.

Together, they provide overlapping coverage. The failure of any single
layer does not compromise the system.

## Decision 4: Allowlist Over Blocklist

**Choice:** Tool authorizer uses an explicit allowlist of permitted tools
and valid parameter patterns.

**Alternatives considered:** Blocklist of dangerous tools/patterns.

**Rationale:**
Blocklists are always incomplete. You can't enumerate every possible
attack — new techniques are discovered constantly. Allowlists fail
safely: if something isn't explicitly permitted, it's denied.

This applies at three levels:
1. Tool names (only 4 tools are registered)
2. Parameter characters (strict regex allowlists)
3. File paths (only files within LOG_DIRECTORY)

## Decision 5: Human-in-the-Loop for Sensitive Tools

**Choice:** Tools that read files or execute subprocesses require explicit
user confirmation before execution.

**Alternatives considered:** Full autonomy with logging, no autonomy at all.

**Rationale:**
CSA's Agentic AI Security Scoping Matrix defines four levels of agency.
This agent is Scope 2 (Prescribed Agency): "Human approval required for
all actions with limited autonomous capabilities."

We split tools into two categories:
- **Safe tools** (system_info, health_check): No side effects, no
  sensitive data. These run automatically.
- **Sensitive tools** (read_log, search_logs): Access files or run
  subprocesses. These require confirmation.

The confirmation prompt shows exactly what will be executed — tool name,
all parameters, no hidden state.

## Decision 6: Dual Audit Logging

**Choice:** Both the agent AND the MCP server maintain independent audit logs.

**Rationale:**
If either component is compromised, the other's logs still provide a
forensic trail. Discrepancies between the logs indicate tampering.

Agent-side log: Records input validation, tool authorization decisions,
output filtering actions.

Server-side log: Records tool invocations, parameter keys (not values),
execution results, errors.

Both use JSONL (append-only, one JSON object per line) for easy parsing
with standard tools.

## Decision 7: Generic Error Messages

**Choice:** MCP server tools return user-friendly error messages, never
stack traces or internal details.

**Rationale:**
Detailed error messages are a well-known information disclosure vector.
A stack trace can reveal:
- Internal file paths
- Library versions (useful for known-CVE attacks)
- Database schemas
- Authentication logic

Our tools catch all exceptions and return generic messages like
"Unable to read the specified log file." The actual error is logged
to the server-side audit log for the operator, not exposed to the model.

## Decision 8: No shell=True (Anywhere)

**Choice:** All subprocess calls use argument lists with shell=False.

**Rationale:**
This is the single most impactful security control in the MCP server.
The vulnerable demo server in the AI Red Team Orchestrator uses:

```python
# VULNERABLE
cmd = f"cat /var/log/{path}"
subprocess.check_output(cmd, shell=True)
```

This allows arbitrary command execution through parameter manipulation.
Our server uses:

```python
# SECURE
subprocess.run(["grep", "-n", keyword, str(path)], shell=False)
```

With shell=False, the arguments are passed directly to the executable
as a list. Shell metacharacters (;, |, &&, $(), `) have no special
meaning — they're just literal characters.
