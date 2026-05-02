# 🏗️ Secure-By-Design-Agentic

**An educational, open-source project demonstrating how to build a secure
AI agent with MCP tool integration — aligned with OWASP, NIST, and CSA frameworks.**

> **Status:** v1 — secure agent + secure MCP server + manual red-team validation.
> Automated red-team integration ships in v2 ([roadmap below](#roadmap)).

> **Purpose:** This project exists to teach. Every architectural decision is
> documented with *why* it was made and *which framework prescription* it
> satisfies. The goal is to give security engineers, developers, and AI
> practitioners a reference implementation they can study, fork, and adapt.

---

## Table of Contents

- [What's in v1](#whats-in-v1)
- [Why This Project Exists](#why-this-project-exists)
- [Architecture Overview](#architecture-overview)
- [Framework Alignment](#framework-alignment)
- [Technology Choices (Justified)](#technology-choices-justified)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [The Two Phases (in v1)](#the-two-phases-in-v1)
- [Manual Red-Team Validation](#manual-red-team-validation)
- [Roadmap](#roadmap)
- [Educational Resources](#educational-resources)
- [Contributing](#contributing)
- [License](#license)

---

## What's in v1

✅ **Phase 1 — A secure agent**
Defense-in-depth architecture with input validation, tool authorization,
output filtering, and structured audit logging. Built without an agent
framework so every security boundary is visible.

✅ **Phase 2 — A secure MCP server**
Hardened FastMCP server with four read-only tools demonstrating path
canonicalization, argument-list subprocess invocation, rate limiting, and
generic error messages.

✅ **Manual red-team validation**
Test cases from OWASP LLM01, LLM02, LLM05, LLM06, and LLM10 that you can run
by hand to verify each defense layer. See [`docs/MANUAL_REDTEAM.md`](docs/MANUAL_REDTEAM.md).

✅ **Static analysis with mcp-scan**
The most stable component of the red-team toolchain runs in CI on every push.

🛠️ **Coming in v2** — full automated red-team pipeline using
[AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator)
once that project produces consistent results across runs.

---

## Why This Project Exists

AI agents with tool access are proliferating across enterprises. NIST research
(January 2025) demonstrated that novel attack strategies against AI agents
achieved an **81% success rate** in red-team exercises, compared to 11%
against baseline defenses. Meanwhile, a January 2026 scan of 1,808 public MCP
servers found that **43% had command injection vulnerabilities**, 13% had
authentication bypasses, and 10% had path traversal issues.

The gap between "deploy an AI agent" and "deploy a *secure* AI agent" is
enormous. This project bridges it by:

1. Building a **secure agent** designed with least privilege, human-in-the-loop,
   and defense-in-depth from day one
2. Building a **secure MCP server** demonstrating mitigations against the real
   vulnerabilities found in production MCP deployments
3. Providing a **manual red-team checklist** (v1) that becomes an **automated
   pipeline** (v2) once the upstream tooling stabilizes

Each component is annotated with the specific OWASP, NIST, or CSA control it
implements.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                      User Interface                      │
│              (CLI with human-in-the-loop)                │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                   Secure Agent Layer                     │
│                                                         │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐  │
│  │ Input Guard  │  │ System Prompt│  │ Output Filter │  │
│  │ (Validator)  │  │ (Constrained)│  │  (Sanitizer)  │  │
│  └──────┬──────┘  └──────┬───────┘  └───────┬───────┘  │
│         │                │                   │          │
│         ▼                ▼                   ▼          │
│  ┌──────────────────────────────────────────────────┐   │
│  │              LLM (Ollama — qwen2.5:7b)           │   │
│  └──────────────────────┬───────────────────────────┘   │
│                         │                               │
│  ┌──────────────────────▼───────────────────────────┐   │
│  │           Tool Call Authorization Layer           │   │
│  │  • Allowlist enforcement                         │   │
│  │  • Parameter validation                          │   │
│  │  • Human confirmation for destructive ops        │   │
│  │  • Audit logging                                 │   │
│  └──────────────────────┬───────────────────────────┘   │
└─────────────────────────┼───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Secure MCP Server (FastMCP)                 │
│                                                         │
│  ┌────────────────┐  ┌────────────────┐                 │
│  │  read_log       │  │  system_info    │                │
│  │  (path-locked)  │  │  (read-only)    │                │
│  └────────────────┘  └────────────────┘                 │
│  ┌────────────────┐  ┌────────────────┐                 │
│  │  search_logs    │  │  health_check   │                │
│  │  (grep-only)    │  │  (no params)    │                │
│  └────────────────┘  └────────────────┘                 │
│                                                         │
│  Security controls:                                     │
│  • No shell=True anywhere                               │
│  • Path canonicalization + allowlist                     │
│  • Input type validation on every parameter              │
│  • Tool descriptions free of secrets                    │
│  • Rate limiting                                        │
│  • Audit trail on every invocation                      │
└─────────────────────────────────────────────────────────┘
```

---

## Framework Alignment

Every design decision maps to a specific control or recommendation. The full
control-level mapping is in [`docs/FRAMEWORK_ALIGNMENT.md`](docs/FRAMEWORK_ALIGNMENT.md).

| Decision | OWASP | NIST | CSA |
|---|---|---|---|
| Input validation on all tool params | LLM01 (Prompt Injection) | AI 600-1 §5.1 | AICM AIS-04 |
| Output sanitization (sensitive patterns) | LLM05 (Improper Output Handling) | AI 600-1 §5.5 | AICM AIS-07 |
| Tool allowlist enforcement | LLM06 (Excessive Agency — Functionality) | AI 100-1 MAP 1.5 | AICM AIS-09 |
| Human confirmation for destructive ops | LLM06 (Excessive Agency — Autonomy) | AI 100-1 GOVERN 1.4 | Scoping Matrix Scope 2 |
| No secrets in system prompt | LLM07 (System Prompt Leakage) | AI 600-1 §5.7 | AICM IAM-03 |
| Path canonicalization | OWASP MCP Guide §4.3 | SP 800-53 SI-10 | AICM AIS-05 |
| No `shell=True` in subprocess calls | OWASP MCP Guide §4.2 | SP 800-53 SI-10 | AICM AIS-05 |
| Audit logging of tool invocations | LLM09 (Misinformation) | AI 100-1 MEASURE 2.6 | AICM LOG-01 |
| Rate limiting | LLM10 (Unbounded Consumption) | AI 600-1 §5.10 | AICM AIS-12 |
| Sensitive pattern filtering | LLM02 (Sensitive Info Disclosure) | AI 600-1 §5.2 | AICM DSP-04 |
| Tool descriptions reviewed for poisoning | OWASP MCP Security Guide | — | AICM AIS-06 |

---

## Technology Choices (Justified)

Each technology was selected for a specific reason. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full decision log.

### Runtime & Model

| Technology | Why |
|---|---|
| **Python 3.11+** | Primary language for all major red-team frameworks (PyRIT, Garak, Promptfoo plugins). Keeps the v2 pipeline in one ecosystem. |
| **Ollama** | Fully local inference — no API keys, no data exfiltration risk, no vendor lock-in. Essential for security testing where you control the full stack. |
| **qwen2.5:7b** | Open-weight model (Apache 2.0), fits on consumer hardware (8GB VRAM). Large enough for realistic agent behavior, small enough for rapid iteration. |
| **uv** | Deterministic dependency resolution with lockfiles. Critical for reproducible security testing. |

### Agent Architecture

| Technology | Why |
|---|---|
| **No framework (vanilla Python)** | Agent frameworks (LangChain, CrewAI, etc.) abstract away the exact control surfaces we're trying to secure. NIST AI 100-1 GOVERN 1.1 requires understanding of the system's full attack surface. |
| **Ollama Python SDK** | Thin client, minimal dependency surface. Directly maps to `POST /api/chat` — no hidden middleware. |

### MCP Server

| Technology | Why |
|---|---|
| **FastMCP** | Reference implementation from the MCP specification authors. Ensures protocol compliance with minimal surface area. |
| **No `shell=True`** | OWASP MCP Guide §4.2 explicitly prohibits shell-mediated subprocess calls. We use `subprocess.run([...], shell=False)` with argument lists. |
| **`pathlib` for path ops** | `os.path.realpath()` + prefix checking prevents path traversal. OWASP MCP Guide §4.3. |

### What We Deliberately Did NOT Use

| Omission | Rationale |
|---|---|
| **LangChain / LlamaIndex** | Hides the agent loop behind abstractions. For security education, every decision point must be inspectable. |
| **API-based models (OpenAI, Anthropic)** | Can't fully red-team what you don't control. Local inference is required for reproducible adversarial testing in v2. |
| **Docker (for the agent)** | Adds a layer that obscures the security boundaries. Process-level isolation is what we're teaching. Docker is fine for deployment; it's wrong for learning. |

---

## Project Structure

```
Secure-By-Design-Agentic/
│
├── README.md                          # This file
├── LICENSE                            # MIT
├── pyproject.toml                     # Project metadata + dependencies
│
├── agent/                             # Phase 1 — The Secure Agent
│   ├── __init__.py
│   ├── agent.py                       # Main agent loop
│   ├── input_guard.py                 # Input validation & sanitization
│   ├── output_filter.py               # Output sanitization (sensitive patterns)
│   ├── tool_authorizer.py             # Tool call authorization layer
│   ├── audit_logger.py                # Structured audit logging
│   └── config.py                      # Agent configuration (no secrets)
│
├── mcp_server/                        # Phase 2 — The Secure MCP Server
│   ├── __init__.py
│   ├── server.py                      # FastMCP server with hardened tools
│   ├── validators.py                  # Input validation utilities
│   ├── rate_limiter.py                # Token-bucket rate limiter
│   └── audit.py                       # Server-side audit logging
│
├── redteam-v2-preview/                # ⚠️  Scaffolding for v2 — NOT used in v1
│   ├── README.md                      # Explains the v2 status
│   ├── mcp_client_config.json         # Used by mcp-scan in CI
│   └── run_redteam.sh                 # Wrapper for the orchestrator (v2)
│
├── docs/                              # Educational documentation
│   ├── ARCHITECTURE.md                # Architecture decision log
│   ├── FRAMEWORK_ALIGNMENT.md         # Full OWASP/NIST/CSA mapping
│   ├── THREAT_MODEL.md                # STRIDE threat model
│   └── MANUAL_REDTEAM.md              # v1 manual validation suite
│
└── .github/
    └── workflows/
        └── ci.yml                     # v1 CI: lint + import smoke test + mcp-scan
```

---

## Prerequisites

| Tool | Install | Purpose |
|---|---|---|
| [Python 3.11+](https://python.org) | System or `pyenv` | Runtime |
| [uv](https://docs.astral.sh/uv/) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | Dependency management |
| [Ollama](https://ollama.com) | `curl -fsSL https://ollama.com/install.sh \| sh` | Local LLM inference |
| [Node.js 18+](https://nodejs.org) | System package manager | `npx` for `mcp-scan` |

```bash
# Start Ollama and pull the model
ollama serve &
ollama pull qwen2.5:7b
```

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/josephManzambi/Secure-By-Design-Agentic.git
cd Secure-By-Design-Agentic

# Install dependencies
uv sync

# --- Run the secure agent ---
uv run python -m agent.agent

# --- Run the secure MCP server standalone (for testing) ---
uv run python -m mcp_server.server

# --- Run mcp-scan against the MCP server ---
npx -y mcp-scan@latest scan -c redteam-v2-preview/mcp_client_config.json --json
```

---

## The Two Phases (in v1)

### Phase 1 — The Secure Agent

The agent implements a **defense-in-depth** architecture with four security layers:

1. **Input Guard** — Validates user input before it reaches the LLM. Detects
   prompt injection patterns, encoding attacks, and excessively long inputs.
   *(OWASP LLM01, NIST AI 600-1 §5.1)*

2. **Constrained System Prompt** — Defines the agent's role, lists allowed
   tools, and instructs the model to refuse out-of-scope requests. Critically,
   **no secrets are stored here** — the system prompt is treated as public
   information. *(OWASP LLM07, NIST AI 600-1 §5.7)*

3. **Tool Authorization Layer** — Intercepts every tool call from the LLM,
   validates against an allowlist, checks parameter types and ranges, and
   requires human confirmation for sensitive operations.
   *(OWASP LLM06, CSA Scoping Matrix Scope 2)*

4. **Output Filter** — Scans LLM responses for sensitive patterns (file paths,
   credentials, PII) before display. *(OWASP LLM02, LLM05)*

### Phase 2 — The Secure MCP Server

The MCP server exposes four tools, each demonstrating a different security
pattern:

- **`read_log`** — Reads log files from a locked directory. Demonstrates path
  canonicalization, allowlisted directories, and file extension validation.
- **`system_info`** — Returns system metadata. Read-only, no parameters —
  demonstrates the principle of minimal functionality.
- **`search_logs`** — Searches log files by keyword. Demonstrates safe
  subprocess usage (argument lists, no shell), input length limits, and
  character allowlists.
- **`health_check`** — Returns server status. No parameters, no side effects —
  demonstrates a "safe default" tool.

---

## Manual Red-Team Validation

v1 ships with a manual test suite covering OWASP LLM01, LLM02, LLM05, LLM06,
and LLM10. The full suite — with expected behavior, audit log entries, and
explanations — lives in [`docs/MANUAL_REDTEAM.md`](docs/MANUAL_REDTEAM.md).

Three categories:

1. **Static analysis** — `mcp-scan` against the secure server (passes in CI)
2. **Direct prompt injection** — verifying the Input Guard catches obvious attacks
3. **Tool-layer attacks** — verifying the Tool Authorizer blocks unauthorized
   calls even when the LLM would comply

Each test case lists the attack, the expected defense response, and the
audit log entry that should appear.

---

## Roadmap

### v1 (current) — Secure Foundation
- [x] Secure agent with four-layer defense-in-depth
- [x] Hardened MCP server with four tools
- [x] Threat model + framework alignment docs
- [x] Manual red-team validation suite
- [x] CI: lint + import smoke test + mcp-scan

### Between v1 and v2 — Stabilizing the Orchestrator
- [ ] Resolve PyRIT version-pinning issues in
      [ai-redteam-orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator)
- [ ] Verify three consecutive runs produce consistent severity classifications
- [ ] Document failure modes encountered during stabilization

### v2 — Full Automated Red-Team Integration
- [ ] Wire the orchestrator into the project (move `redteam-v2-preview/` → `redteam/`)
- [ ] Add the three-layer pipeline to CI (Layer 1 broad scan, Layer 2 OWASP +
      mcp-scan, Layer 3 PyRIT adversarial)
- [ ] Run the full pipeline against the secure agent + MCP server
- [ ] Commit the resulting report to `docs/RESULTS.md` for transparency

### Future considerations
- [ ] Add a deliberately vulnerable MCP server alongside the secure one for
      side-by-side teaching
- [ ] SBOM generation (OWASP LLM03 — Supply Chain)
- [ ] Compare results across different Ollama models
- [ ] Container isolation example (production-grade deployment)

---

## Educational Resources

### Frameworks Referenced

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Practical Guide for Secure MCP Server Development](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/) (Feb 2026)
- [OWASP Guide for Securely Using Third-Party MCP Servers](https://genai.owasp.org/resource/cheatsheet-a-practical-guide-for-securely-using-third-party-mcp-servers-1-0/) (Apr 2026)
- [NIST AI Risk Management Framework (AI 100-1)](https://www.nist.gov/itl/ai-risk-management-framework)
- [NIST AI 600-1 — Generative AI Profile](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf)
- [CSA AI Controls Matrix (AICM)](https://cloudsecurityalliance.org/artifacts/ai-controls-matrix)
- [CSA Agentic AI Security Scoping Matrix](https://cloudsecurityalliance.org/blog/2025/12/16/enhancing-the-agentic-ai-security-scoping-matrix-a-multi-dimensional-approach)

### Related Projects

- [AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator) — The red-team pipeline that ships in v2
- [Lance](https://github.com/josephManzambi/lance) — Advanced AI security testing framework (in development)

---

## Contributing

This is an educational project. Contributions that improve security coverage,
add framework mappings, or enhance documentation are welcome. Please:

1. Fork the repo
2. Create a feature branch
3. Submit a PR with a clear description of *what* and *why*

---

## License

[MIT](LICENSE)

---

## Author

**Joseph Manzambi** — AI Security Engineer
- Website: [manzambi.com](https://www.manzambi.com)
- GitHub: [@josephManzambi](https://github.com/josephManzambi)
