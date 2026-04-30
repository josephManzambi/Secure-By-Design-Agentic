# Threat Model — Secure-By-Design-Agentic

## System Description

An AI agent powered by a locally-hosted LLM (Ollama/qwen2.5:7b) that provides
system diagnostics capabilities through an MCP server with four tools: log
reading, system info, log searching, and health checking.

## Trust Boundaries

```
┌───────────────────────────────────────────────────────────────┐
│  TRUST BOUNDARY 1: User Interface                            │
│  Threats: Prompt injection, social engineering                │
│  Controls: Input Guard (input_guard.py)                      │
├───────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 2: LLM Decision Layer                        │
│  Threats: Jailbreak, instruction override, hallucination     │
│  Controls: System prompt constraints (soft), Tool authorizer  │
│            (hard)                                            │
├───────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 3: Tool Execution Layer                      │
│  Threats: Unauthorized tool calls, parameter manipulation    │
│  Controls: Allowlist, parameter validation, human-in-the-loop│
├───────────────────────────────────────────────────────────────┤
│  TRUST BOUNDARY 4: MCP Server / System Resources             │
│  Threats: Path traversal, command injection, data exfil      │
│  Controls: Path canonicalization, shell=False, rate limiting  │
└───────────────────────────────────────────────────────────────┘
```

## Threat Categories (STRIDE)

### Spoofing
| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| User impersonates admin via prompt | HIGH | HIGH | Input guard detects role hijacking patterns; tool authorizer enforces allowlist regardless of LLM state |
| Indirect prompt injection via log file contents | MEDIUM | HIGH | Output filter scans for sensitive patterns; LLM instructed to ignore instructions in tool outputs |

### Tampering
| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| LLM manipulated to call unauthorized tools | HIGH | CRITICAL | Tool authorizer allowlist is deterministic — LLM cannot bypass |
| Path traversal to read files outside log dir | HIGH | CRITICAL | Path canonicalization + prefix check + character allowlist |
| Command injection via tool parameters | HIGH | CRITICAL | No shell=True; argument-list subprocess; parameter validation |

### Repudiation
| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Agent actions not attributable | MEDIUM | MEDIUM | Dual audit logging (agent-side + server-side), JSONL format |

### Information Disclosure
| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| System prompt leakage | HIGH | LOW | Prompt treated as public; no secrets in prompt; output filter flags leakage patterns |
| Sensitive data in tool output | MEDIUM | HIGH | Output filter redacts passwd entries, private keys, API keys, connection strings |
| Error message leaks internals | MEDIUM | MEDIUM | Generic error messages; no stack traces in tool responses |

### Denial of Service
| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Rapid tool call flooding | MEDIUM | MEDIUM | Token-bucket rate limiter per tool + global |
| Large file read exhaustion | LOW | MEDIUM | 10 MB file size limit; max input length on prompts |
| Conversation loop exhaustion | LOW | LOW | Max conversation turns limit |

### Elevation of Privilege
| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| LLM escalates from read-only to command exec | HIGH | CRITICAL | No command execution tools exposed; search uses grep with shell=False |
| Multi-turn jailbreak bypasses refusal | HIGH | HIGH | Tool authorizer is stateless — each call re-validated independently |

## Attack Scenarios Tested by Red Team

| Scenario | Layer | Framework |
|---|---|---|
| Direct prompt injection ("ignore previous instructions") | 1 | Garak, Promptfoo |
| Encoding-based evasion (base64, leetspeak, multilingual) | 1, 2 | Promptfoo OWASP preset |
| Path traversal via read_log ("../../etc/passwd") | 2 | Promptfoo eval, mcp-scan |
| Command injection via search_logs ("; cat /etc/shadow") | 2 | Promptfoo eval, mcp-scan |
| System prompt extraction | 1, 2 | Garak, Promptfoo |
| Gradual escalation over multiple turns | 3 | PyRIT Crescendo |
| Branching jailbreak search | 3 | PyRIT TAP |
| Tool poisoning via descriptions | 2 | mcp-scan |

## Residual Risks

1. **Novel prompt injection techniques**: The input guard uses pattern matching,
   which cannot catch all future injection techniques. This is inherent to the
   LLM security model and is documented by OWASP LLM01.

2. **Model-specific vulnerabilities**: Different LLM versions may have different
   jailbreak susceptibilities. Red-teaming should be re-run when changing models.

3. **Local execution trust**: The agent and MCP server run as the same user. A
   compromised MCP server could affect the agent process. In production, use
   separate user accounts or container isolation.

4. **Ollama API surface**: The Ollama HTTP API at localhost:11434 has no
   authentication. Any local process can interact with it. This is acceptable
   for a local development setup but not for production.
