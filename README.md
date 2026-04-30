# 🏗️ Secure-By-Design-Agentic

**An educational, open-source project demonstrating how to build, secure, and red-team an AI agent with MCP tool integration — aligned with OWASP, NIST, and CSA frameworks.**

> **Purpose:** This project exists to teach. Every architectural decision is documented with *why* it was made and *which framework prescription* it satisfies. The goal is to give security engineers, developers, and AI practitioners a reference implementation they can study, fork, and adapt.

---

## Table of Contents

- [Why This Project Exists](#why-this-project-exists)
- [Architecture Overview](#architecture-overview)
- [Framework Alignment](#framework-alignment)
- [Technology Choices (Justified)](#technology-choices-justified)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [The Three Phases](#the-three-phases)
- [Red Team Results](#red-team-results)
- [Educational Resources](#educational-resources)
- [TODO](#todo)
- [Contributing](#contributing)
- [License](#license)

---

## Why This Project Exists

AI agents with tool access are proliferating across enterprises. NIST's research
(January 2025) demonstrated that novel attack strategies against AI agents achieved
an **81% success rate** in red-team exercises, compared to 11% against baseline
defenses. Meanwhile, a January 2026 scan of 1,808 public MCP servers found that
**43% had command injection vulnerabilities**, 13% had authentication bypasses, and
10% had path traversal issues.

The gap between "deploy an AI agent" and "deploy a *secure* AI agent" is enormous.
This project bridges it by building three things in sequence:

1. **A secure agent** — designed with least privilege, human-in-the-loop, and
   defense-in-depth from day one
2. **A secure MCP server** — demonstrating every mitigation against the real
   vulnerabilities found in production MCP deployments
3. **A red-team pipeline** — using the
   [AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator)
   to validate that the defenses actually hold

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

Every design decision maps to a specific control or recommendation:

| Decision | OWASP | NIST | CSA |
|---|---|---|---|
| Input validation on all tool params | LLM01 (Prompt Injection) | AI 600-1 §5.1 | AICM AIS-04 |
| Output sanitization (strip sensitive patterns) | LLM05 (Improper Output Handling) | AI 600-1 §5.5 | AICM AIS-07 |
| Tool allowlist (agent can only call registered tools) | LLM06 (Excessive Agency — Functionality) | AI 100-1 MAP 1.5 | AICM AIS-09 |
| Human confirmation for destructive operations | LLM06 (Excessive Agency — Autonomy) | AI 100-1 GOVERN 1.4 | Scoping Matrix Scope 2 |
| No secrets in system prompt or tool descriptions | LLM07 (System Prompt Leakage) | AI 600-1 §5.7 | AICM IAM-03 |
| Path canonicalization in MCP tools | LLM05 + OWASP MCP Guide | SP 800-53 SI-10 | AICM AIS-05 |
| No shell=True in subprocess calls | LLM05 + OWASP MCP Guide | SP 800-53 SI-10 | AICM AIS-05 |
| Audit logging of all tool invocations | LLM09 (Misinformation) | AI 100-1 MEASURE 2.6 | AICM LOG-01 |
| Rate limiting on MCP server | LLM10 (Unbounded Consumption) | AI 600-1 §5.10 | AICM AIS-12 |
| Sensitive pattern filtering in output | LLM02 (Sensitive Info Disclosure) | AI 600-1 §5.2 | AICM DSP-04 |
| Tool descriptions reviewed for poisoning | OWASP MCP Security Guide | — | AICM AIS-06 |
| Red-team testing with multiple strategies | LLM01, LLM06 | AI 100-2.1 | AICM AIS-14 |

---

## Technology Choices (Justified)

Each technology was selected for a specific reason. No tool is included "because
it's popular" — every choice has a security or educational rationale.

### Runtime & Model

| Technology | Why |
|---|---|
| **Python 3.11+** | Primary language for all three major red-team frameworks (PyRIT, Garak, Promptfoo plugins). Keeps the entire pipeline in one ecosystem. |
| **Ollama** | Fully local inference — no API keys, no data exfiltration risk, no vendor lock-in. Essential for security testing where you control the full stack. |
| **qwen2.5:7b** | Open-weight model that fits on consumer hardware (8GB VRAM). Large enough to exhibit realistic agent behavior, small enough for rapid iteration. Apache 2.0 licensed. |
| **uv** | Deterministic dependency resolution with lockfiles. Critical for reproducible security testing — you need to know exactly what versions ran. |

### Agent Framework

| Technology | Why |
|---|---|
| **No framework (vanilla Python)** | Deliberate choice. Agent frameworks (LangChain, CrewAI, etc.) abstract away the exact control surfaces we're trying to secure. Building from scratch means every security boundary is visible, auditable, and educational. NIST AI 100-1 GOVERN 1.1 requires understanding of the system's full attack surface. |
| **Ollama Python SDK** | Thin client, minimal dependency surface. Directly maps to `POST /api/chat` — no hidden middleware. |

### MCP Server

| Technology | Why |
|---|---|
| **FastMCP** | Reference implementation from the MCP specification authors. Ensures protocol compliance. Minimal surface area compared to custom implementations. |
| **No shell=True** | OWASP MCP Guide §4.2 explicitly prohibits shell-mediated subprocess calls. We use `subprocess.run([...], shell=False)` with argument lists. |
| **pathlib for path ops** | `os.path.realpath()` + prefix checking prevents path traversal. OWASP MCP Guide §4.3. |

### Red Team Pipeline

| Technology | Why |
|---|---|
| **[AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator)** | Integrates four frameworks in a single pipeline. Produces auditable Markdown/HTML reports with severity classification. |
| **Garak (NVIDIA)** | Broadest probe coverage: prompt injection, encoding tricks, social engineering, leak replay. NIST AI 100-2.1 recommends diverse attack surface coverage. |
| **Promptfoo** | OWASP LLM Top-10 plugin bundle maps directly to the taxonomy. Generates adversarial test cases with multiple evasion strategies (jailbreak, multilingual, base64, leetspeak). |
| **PyRIT (Microsoft)** | Multi-turn orchestrators (Crescendo, TAP) test refusal persistence — a single-turn test can't find gradual-escalation vulnerabilities. NIST AI 600-1 §5.1 calls out multi-turn attacks specifically. |
| **mcp-scan (Invariant Labs)** | Static analysis of MCP tool descriptors — finds tool poisoning and prompt injection vectors that runtime testing misses. Complements dynamic testing. |

### What We Deliberately Did NOT Use

| Omission | Rationale |
|---|---|
| **LangChain / LlamaIndex** | Hides the agent loop behind abstractions. For security education, we need every decision point to be inspectable. |
| **API-based models (OpenAI, Anthropic)** | Can't red-team what you don't control. Local inference is required for reproducible, unrestricted adversarial testing. |
| **Docker (for the agent)** | Adds a layer that obscures the security boundaries. The MCP server runs as a subprocess — its isolation is at the process level, which is what we're teaching. Docker is fine for deployment; it's wrong for learning. |

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
│   ├── output_filter.py              # Output sanitization (sensitive patterns)
│   ├── tool_authorizer.py            # Tool call authorization layer
│   ├── audit_logger.py               # Structured audit logging
│   └── config.py                      # Agent configuration (no secrets)
│
├── mcp_server/                        # Phase 2 — The Secure MCP Server
│   ├── __init__.py
│   ├── server.py                      # FastMCP server with hardened tools
│   ├── validators.py                  # Input validation utilities
│   ├── rate_limiter.py               # Token-bucket rate limiter
│   └── audit.py                       # Server-side audit logging
│
├── redteam/                           # Phase 3 — Red Team Configuration
│   ├── mcp_client_config.json         # mcp-scan target descriptor
│   ├── promptfoo_broad.json           # Layer 1 Promptfoo config
│   ├── promptfoo_owasp.json           # Layer 2 OWASP config
│   └── run_redteam.sh                 # Wrapper to invoke the orchestrator
│
├── docs/                              # Educational documentation
│   ├── ARCHITECTURE.md                # Detailed architecture decisions
│   ├── FRAMEWORK_ALIGNMENT.md         # Full OWASP/NIST/CSA mapping
│   ├── THREAT_MODEL.md                # Threat model for this system
│   └── ARTICLE_OUTLINE.md            # Outline for the blog/LinkedIn content
│
└── .github/
    └── workflows/
        └── security-audit.yml         # CI pipeline for automated red-teaming
```

---

## Prerequisites

| Tool | Install | Purpose |
|---|---|---|
| [Python 3.11+](https://python.org) | System or `pyenv` | Runtime |
| [uv](https://docs.astral.sh/uv/) | `curl -LsSf https://astral.sh/uv/install.sh \| sh` | Dependency management |
| [Ollama](https://ollama.com) | `curl -fsSL https://ollama.com/install.sh \| sh` | Local LLM inference |
| [Node.js 18+](https://nodejs.org) | System package manager | `npx` for Promptfoo, mcp-scan |

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

# --- Phase 1: Run the secure agent ---
uv run python -m agent.agent

# --- Phase 2: Run the secure MCP server standalone (for testing) ---
uv run python -m mcp_server.server

# --- Phase 3: Red-team everything ---
# Option A: Use the AI Red Team Orchestrator directly
uv run redteam_orchestrator.py \
  --mcp-config redteam/mcp_client_config.json \
  --layers 1,2,3 --html

# Option B: Use the wrapper script
bash redteam/run_redteam.sh
```

---

## The Three Phases

### Phase 1 — Build the Secure Agent

The agent implements a **defense-in-depth** architecture with four security layers:

1. **Input Guard** — Validates and sanitizes user input before it reaches the LLM.
   Detects and flags prompt injection patterns, encoding attacks, and
   excessively long inputs. *(OWASP LLM01, NIST AI 600-1 §5.1)*

2. **Constrained System Prompt** — Defines the agent's role, explicitly lists
   allowed tools, and instructs the model to refuse out-of-scope requests. But
   critically, **no secrets are stored here** — the system prompt is treated as
   public information. *(OWASP LLM07, NIST AI 600-1 §5.7)*

3. **Tool Authorization Layer** — Intercepts every tool call from the LLM,
   validates it against an allowlist, checks parameter types and ranges, and
   requires human confirmation for any operation classified as destructive.
   *(OWASP LLM06, CSA Scoping Matrix Scope 2)*

4. **Output Filter** — Scans LLM responses for sensitive patterns (file paths,
   credentials, PII) before displaying to the user. *(OWASP LLM02, LLM05)*

### Phase 2 — Build the Secure MCP Server

The MCP server exposes four tools, each demonstrating a different security
pattern:

- **`read_log`** — Reads log files from a locked directory. Demonstrates path
  canonicalization, allowlisted directories, and file extension validation.
- **`system_info`** — Returns system metadata (hostname, uptime, OS). Read-only,
  no parameters — demonstrates the principle of minimal functionality.
- **`search_logs`** — Searches log files by keyword. Demonstrates safe
  subprocess usage (argument lists, no shell), input length limits, and regex
  sanitization.
- **`health_check`** — Returns server status. No parameters, no side effects —
  demonstrates a "safe default" tool.

### Phase 3 — Red-Team Everything

Uses the [AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator)
to test the full stack:

| Layer | What It Tests | Tools |
|---|---|---|
| Layer 1 — Broad Scan | LLM prompt injection resistance, encoding attacks, social engineering | Garak + Promptfoo eval |
| Layer 2 — Compliance | OWASP LLM Top-10 coverage + MCP tool surface analysis | Promptfoo OWASP preset + mcp-scan |
| Layer 3 — Adversarial | Multi-turn jailbreak persistence, gradual escalation | PyRIT Crescendo + TAP |

---

## Red Team Results

*This section will be populated after running the orchestrator against the
secure agent + MCP server. The report will be committed to `docs/` for
transparency.*

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

- [AI Red Team Orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator) — The red-team pipeline used in Phase 3
- [Lance](https://github.com/josephManzambi/lance) — Advanced AI security testing framework (in development)

---

## TODO

- [ ] **Phase 1:** Implement and test the secure agent
- [ ] **Phase 2:** Implement and test the secure MCP server
- [ ] **Phase 3:** Run full red-team audit and document results
- [ ] **Docs:** Write THREAT_MODEL.md
- [ ] **Docs:** Write detailed FRAMEWORK_ALIGNMENT.md with control-level mappings
- [ ] **Content:** Write LinkedIn article (hook piece, ~600 words)
- [ ] **Content:** Write full deep-dive article for [manzambi.com/writing](https://www.manzambi.com/writing)
- [ ] **CI:** Set up GitHub Actions for automated security audit
- [ ] **Extend:** Add a deliberately vulnerable MCP server for comparison
- [ ] **Extend:** Add SBOM generation (OWASP LLM03 — Supply Chain)

---

## Contributing

This is an educational project. Contributions that improve security coverage,
add framework mappings, or enhance documentation are welcome. Please:

1. Fork the repo
2. Create a feature branch
3. Submit a PR with a clear description of *what* and *why*

Security issues should be reported via GitHub Issues (this is an educational
project — responsible disclosure is not required for intentionally vulnerable
components).

---

## License

[MIT](LICENSE)

---

## Author

**Joseph Manzambi** — AI Security Engineer
- Website: [manzambi.com](https://www.manzambi.com)
- GitHub: [@josephManzambi](https://github.com/josephManzambi)
