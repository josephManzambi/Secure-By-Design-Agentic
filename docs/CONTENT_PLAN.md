# Content Plan — Three-Article Series

This project anchors a series of three articles on manzambi.com (with LinkedIn
companion posts), released alongside the v1 → orchestrator → v2 milestones.

---

## Article 1 — "Building a Secure-By-Design AI Agent with MCP Tools" (v1)

**Status:** Draft after v1 ships
**Length:** ~2,500 words
**Anchored by:** This repo (v1) — agent + secure MCP server + manual red-team validation

### Hook
The 43% statistic from January 2026: nearly half of public MCP servers have
command injection vulnerabilities. Most teams are deploying agents faster than
they're learning to secure them.

### Structure

**1. The Problem (~300 words)**
- Adoption speed vs. security maturity
- 43% of MCP servers have command injection (mcp-scan study, Jan 2026)
- Why this matters now: agents are touching production systems

**2. What "Secure-By-Design" Actually Means (~400 words)**
- Three frameworks converging in 2025-2026: OWASP LLM Top 10, NIST AI 600-1, CSA AICM
- The CSA Agentic Scoping Matrix and where this agent sits (Scope 2)
- Defense-in-depth instead of single-layer security

**3. Architecture Walkthrough (~700 words)**
- Diagram of the four security layers
- Input Guard — what it catches (with one concrete code snippet)
- Tool Authorizer — the deterministic boundary that survives jailbreaks
- Output Filter — defense in depth for sensitive data
- Audit Logger — dual-layer JSONL trail
- Why no LangChain (the abstraction problem for security education)

**4. The MCP Server: Vulnerable vs. Hardened (~600 words)**
- Side-by-side: command injection example (vulnerable demo vs. this server)
- Side-by-side: path traversal (vulnerable vs. this server)
- The single most important rule: never `shell=True`
- Tool descriptions as untrusted (OWASP MCP Guide)

**5. Manual Validation (~400 words)**
- Three test cases that demonstrate the layers working:
  - mcp-scan static analysis result
  - Direct prompt injection blocked at Input Guard
  - Path traversal blocked at Tool Authorizer
- The honest caveat: this is manual. Automated testing is v2.

**6. What's Next (~200 words)**
- v2 will add the full red-team orchestrator pipeline
- The orchestrator itself is the subject of Article 2

### LinkedIn companion (~500 words)
- Hook: 43% stat
- 2-paragraph summary of the architecture
- One concrete code diff (vulnerable vs. secure)
- Link to full article on manzambi.com

---

## Article 2 — "What I Learned Debugging an AI Red-Team Orchestrator"

**Status:** Draft as the orchestrator stabilizes
**Length:** ~2,000 words
**Anchored by:** [ai-redteam-orchestrator](https://github.com/josephManzambi/ai-redteam-orchestrator) repo

### Hook
"I built an AI red-team tool that integrates four frameworks. Then I tried to
run it three times and got three different answers. Here's what was actually
broken."

### Structure

**1. The Promise of Orchestration (~250 words)**
- Why a single-file pipeline matters
- Three layers: broad scan → compliance → adversarial
- The dream: run once, get a complete audit

**2. Reality Check — The Inconsistencies (~400 words)**
- Symptoms: results changing run-to-run, false negatives in scoring
- The instinct to blame the LLM (and why that's usually wrong)
- The actual culprits, in order discovered:
  - PyRIT version drift (0.8 → 0.9 broke `pyrit.orchestrator`)
  - Promptfoo silently falling back to OpenAI when grader fails
  - Garak probe names changing between versions (xss/glitch removed)
  - mcp-scan exit codes (non-zero on findings, not errors)
  - Promptfoo exit code 100 (assertions failed = signal, not failure)

**3. The Fixes (~600 words)**
- Pinning PyRIT to 0.8.1 (with documentation explaining why)
- Adding `defaultTest.options.provider` to keep evals offline
- Reclassifying exit codes in `run_step` so signal isn't treated as error
- Building a regression test suite that pins the contracts that broke

**4. Why Tools Drift Faster Than Documentation (~400 words)**
- The pace of change in the AI security tooling ecosystem
- Why version pinning matters more for security tools than typical software
- The hidden cost of "latest" in CI pipelines

**5. What Reliable Looks Like Now (~250 words)**
- Three runs against the same target → same severity classifications
- Per-step timeout overrides for slow probes
- A test suite that pins the contracts (not just behavior)

**6. What This Means for Your Red-Team Pipeline (~100 words)**
- If you're using off-the-shelf AI red-team tools, you probably have similar issues
- Version-pin everything; test for regression; treat exit codes carefully

### LinkedIn companion (~400 words)
- Hook: "Three runs, three different answers"
- The 5 failure modes with one-line descriptions
- The lesson: AI security tools drift fast. Pin everything.
- Link to full article + repo

---

## Article 3 — "Red-Teaming My Own Agent: Results from the Full Pipeline" (v2)

**Status:** Draft after v2 ships and the orchestrator runs cleanly against the secure agent
**Length:** ~3,500-4,000 words (the longest of the three — this is the payoff)
**Anchored by:** This repo (v2) — secure agent + reliable orchestrator integration

### Hook
NIST research showed an 81% success rate for novel attacks against AI agents.
"I built one designed to OWASP/NIST/CSA spec, then pointed my own red-team at
it. Here's what survived and what didn't."

### Structure

**1. Setup (~400 words)**
- What v1 was (link to Article 1)
- What v2 added: the full automated pipeline (link to Article 2)
- The methodology: build secure → break it → harden → retest

**2. Layer 1 — Broad Scan Results (~600 words)**
- Garak findings: how the agent responded to prompt injection probes
- Promptfoo broad eval: the four hand-crafted test cases
- What the Input Guard caught vs. what made it through
- One dramatic finding (or "no dramatic findings" — both are honest)

**3. Layer 2 — Compliance Coverage (~700 words)**
- Promptfoo OWASP LLM Top-10 preset results
- Per-category breakdown: which OWASP risks held, which exposed gaps
- mcp-scan results: proving the tool descriptions are clean
- Comparison with the vulnerable demo (the contrast that teaches)

**4. Layer 3 — Adversarial Persistence (~700 words)**
- PyRIT Crescendo: 8 turns of escalation against refusal
- PyRIT TAP: branching jailbreak search
- Why these found things single-turn tests missed
- What multi-turn attacks teach us about the deterministic boundary

**5. The Surprising Part (~400 words)**
- The defense layer that mattered most (probably the Tool Authorizer)
- The defense layer that surprised me by what it caught
- Anything the layers missed (residual risks)

**6. Lessons Beyond This Project (~400 words)**
- System prompts are not security controls (proven, again)
- Allowlists > blocklists (proven, again)
- Deterministic enforcement > stochastic self-restraint (proven, again)
- Red-teaming is continuous, not one-time

**7. The CI Loop (~200 words)**
- Showing the GitHub Actions integration
- How this becomes a regression signal for future changes
- Inviting readers to fork and adapt

**8. Conclusion (~200 words)**
- Series wrap: build → debug tooling → integrate
- Links to all three articles
- Repo links, framework links, newsletter CTA

### LinkedIn companion (~600 words)
- Hook: "I red-teamed my own AI agent. Here's what survived."
- Three layers in three short paragraphs
- One concrete severity table from the report
- The series arc (link to Articles 1, 2, 3 on manzambi.com)
- Tags: #AISecurity #RedTeam #OWASP #MCP #OpenSource

---

## Publishing Cadence

The three articles map to three releases:

| Milestone | Article | Trigger |
|---|---|---|
| Secure-By-Design-Agentic v1 ships | Article 1 | When the manual red-team suite passes |
| AI Red Team Orchestrator stabilizes | Article 2 | After three consistent runs |
| Secure-By-Design-Agentic v2 ships | Article 3 | When the full pipeline runs cleanly |

This creates a natural content arc: build → debug tooling → integrate. Each
article stands alone but links forward and backward.

---

## Cross-Promotion Plan

Each LinkedIn post:
- Links to the full article on manzambi.com
- Links to the GitHub repo
- Tags the relevant frameworks (OWASP GenAI, NIST, CSA)
- Includes one visual: code diff, architecture diagram, or severity table

Each article on manzambi.com:
- Links to the GitHub repo
- Links to all three frameworks
- Newsletter signup CTA
- Forward/backward links between the three articles in the series

---

## TODO

- [ ] **v1 ships** — Article 1 draft
- [ ] **v1 ships** — Article 1 LinkedIn post
- [ ] **Orchestrator stabilizes** — Capture debugging notes as you go
- [ ] **Orchestrator stabilizes** — Article 2 draft
- [ ] **Orchestrator stabilizes** — Article 2 LinkedIn post
- [ ] **v2 ships** — Run the full pipeline, capture report
- [ ] **v2 ships** — Article 3 draft (the big one)
- [ ] **v2 ships** — Article 3 LinkedIn post
- [ ] **Series complete** — Cross-link all three on manzambi.com/writing
