# Framework Alignment — Detailed Control Mapping

This document maps every security control in Secure-By-Design-Agentic to
specific prescriptions from OWASP, NIST, and CSA frameworks.

## OWASP Top 10 for LLM Applications 2025

### LLM01: Prompt Injection

**Risk:** Adversarial inputs that alter the LLM's behavior or bypass safety
instructions. Both direct (user input) and indirect (via tool outputs).

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Input pattern detection | `agent/input_guard.py` | Heuristic regex patterns for known injection techniques (instruction override, delimiter injection, role hijacking) |
| Encoding attack detection | `agent/input_guard.py` | Base64, unicode, and hex obfuscation detection |
| Input length limits | `agent/config.py` | 4096 char max prevents resource exhaustion during injection attempts |
| Tool output isolation | `agent/agent.py` | System prompt instructs model to treat tool outputs as data, not instructions |
| Deterministic tool authorization | `agent/tool_authorizer.py` | Even if injection succeeds and changes model behavior, tool calls are validated independently |

**What we CANNOT prevent:** OWASP acknowledges that "it is unclear if there are
fool-proof methods of prevention for prompt injection." Our approach is
defense-in-depth: the input guard catches obvious attacks, but the real security
boundary is the tool authorizer, which is deterministic and not influenced by
the LLM's state.

### LLM02: Sensitive Information Disclosure

**Risk:** The model leaks sensitive data from tool outputs, training data, or
system configuration in its responses.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Sensitive pattern redaction | `agent/output_filter.py` | Regex-based filtering for passwd entries, private keys, API keys, JWTs, connection strings, internal IPs, email addresses |
| Generic error messages | `mcp_server/server.py` | Tool errors return user-friendly messages, never stack traces or internal paths |
| No secrets in system prompt | `agent/config.py` | The system prompt is treated as public information |
| Audit logging of redactions | `agent/audit_logger.py` | Every redaction is logged for forensic review |

### LLM03: Supply Chain

**Risk:** Compromised dependencies, models, or MCP servers.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Dependency lockfile | `pyproject.toml` | uv generates a lockfile for deterministic builds |
| Minimal dependencies | `pyproject.toml` | Only essential packages; red-team tools are optional extras |
| Open-source model | `agent/config.py` | qwen2.5:7b is Apache 2.0 licensed with published weights |
| Local inference | `agent/config.py` | No external API calls — full control over the inference stack |

**TODO:** Add SBOM generation (CycloneDX or SPDX) per OWASP recommendation.

### LLM05: Improper Output Handling

**Risk:** LLM outputs that contain executable content, injection payloads, or
sensitive data are passed downstream without validation.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Output sanitization | `agent/output_filter.py` | All LLM output passes through the filter before display |
| Tool output validation | `mcp_server/validators.py` | Tool inputs are validated before execution |
| No downstream execution | `agent/agent.py` | Agent output goes to the terminal only — no downstream systems |

### LLM06: Excessive Agency

**Risk:** The agent has too many tools, too many permissions, or too much
autonomy.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Tool allowlist | `agent/tool_authorizer.py` | Only 4 tools are registered; all others are denied |
| Parameter validation | `agent/tool_authorizer.py` | Each tool's parameters are type-checked and pattern-matched |
| Human-in-the-loop | `agent/tool_authorizer.py` | Sensitive tools require explicit user confirmation |
| Max tool calls per turn | `agent/config.py` | 3 tool calls per turn maximum |
| Max conversation turns | `agent/config.py` | 50 turns maximum |
| Read-only tools | `mcp_server/server.py` | No tool can write, delete, or modify system state |

### LLM07: System Prompt Leakage

**Risk:** The system prompt contains sensitive information that the model reveals.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| No secrets in prompt | `agent/config.py` | The system prompt is treated as public information — it contains no credentials, internal paths, or infrastructure details |
| Leakage detection | `agent/output_filter.py` | Flags patterns like "my system prompt is" or "I was instructed to" |
| Prompt extraction detection | `agent/input_guard.py` | Blocks explicit extraction attempts ("print your system prompt") |

### LLM09: Misinformation

**Risk:** The model generates incorrect information that the user acts on.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Audit trail | `agent/audit_logger.py` | Complete record of what the agent actually did vs. what it claimed |
| Tool-grounded responses | `agent/config.py` | System prompt instructs model to use tools rather than guessing |

### LLM10: Unbounded Consumption

**Risk:** The system consumes excessive resources due to large inputs, rapid
requests, or runaway processing.

**Controls implemented:**

| Control | File | Description |
|---|---|---|
| Input length limit | `agent/config.py` | 4096 character maximum |
| Rate limiting | `mcp_server/rate_limiter.py` | Token-bucket rate limiter per tool + global |
| File size limit | `mcp_server/validators.py` | 10 MB maximum file read |
| Search result limit | `mcp_server/validators.py` | 100 result maximum |
| Subprocess timeout | `mcp_server/server.py` | 10-second timeout on grep |
| Conversation turn limit | `agent/config.py` | 50 turns maximum |

---

## NIST AI Risk Management Framework

### AI 100-1 (Core RMF)

| Function | Subcategory | Implementation |
|---|---|---|
| GOVERN 1.1 | System purpose documented | README.md, ARCHITECTURE.md |
| GOVERN 1.4 | Risk response processes | Human-in-the-loop for sensitive tools |
| MAP 1.5 | Attack surface understanding | THREAT_MODEL.md |
| MEASURE 2.6 | Performance monitoring | Audit logging (agent + server side) |
| MANAGE 4.1 | Risk treatment | Red-team pipeline with automated regression |

### AI 600-1 (Generative AI Profile)

| Section | Risk | Implementation |
|---|---|---|
| §5.1 | Prompt injection | Input guard + tool authorizer |
| §5.2 | Sensitive information disclosure | Output filter |
| §5.5 | Improper output handling | Output filter + tool output validation |
| §5.7 | System prompt leakage | No secrets in prompt + leakage detection |
| §5.10 | Unbounded consumption | Rate limiting + input/output limits |

---

## CSA AI Controls Matrix (AICM)

| Domain | Control | Implementation |
|---|---|---|
| AIS-04 | Input validation | `agent/input_guard.py`, `mcp_server/validators.py` |
| AIS-05 | Secure processing | `mcp_server/server.py` (no shell, path canonicalization) |
| AIS-06 | Tool description review | Minimal, factual tool descriptions |
| AIS-07 | Output sanitization | `agent/output_filter.py` |
| AIS-09 | Tool access control | `agent/tool_authorizer.py` (allowlist) |
| AIS-12 | Resource consumption | `mcp_server/rate_limiter.py` |
| AIS-14 | Adversarial testing | Red-team pipeline (Phase 3) |
| DSP-04 | Data sanitization | Output filter (PII, credentials, keys) |
| IAM-03 | Credential management | No secrets in system prompt or tool descriptions |
| LOG-01 | Audit logging | `agent/audit_logger.py`, `mcp_server/audit.py` |

### CSA Agentic AI Security Scoping Matrix

This agent is classified as **Scope 2 (Prescribed Agency)**:

- ✅ Human-initiated (user types input)
- ✅ Human approval required for sensitive actions
- ✅ Limited autonomous capabilities (safe tools only)
- ✅ Fixed workflow paths (4 predefined tools)
- ❌ Not self-initiating
- ❌ Not fully autonomous
