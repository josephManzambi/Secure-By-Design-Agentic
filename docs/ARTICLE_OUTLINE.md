# Article Outline — Content Plan

## Piece 1: LinkedIn Article (~600 words)

**Title ideas:**
- "I Red-Teamed My Own AI Agent — Here's What Broke (and What Held)"
- "81% of AI Agents Fail Red-Team Tests. Mine Didn't. Here's How."
- "Build → Break → Fix: The Missing Step in AI Agent Development"

**Structure:**
1. **Hook** (2 sentences): NIST stat — 81% success rate for attacks on AI agents.
   Why this matters for anyone deploying agents in production.
2. **The problem** (1 paragraph): Most teams build agents, skip security. MCP
   servers are the new attack surface — 43% have command injection vulns.
3. **The approach** (2 paragraphs): Three-phase methodology:
   - Build with OWASP/NIST/CSA controls baked in
   - Red-team with automated pipeline (4 frameworks, 3 layers)
   - Document what held and what didn't
4. **One dramatic finding** (1 paragraph): The most interesting result from
   the red team run. What the attack tried, what the defense did.
5. **Key takeaway** (2 sentences): Security is not a feature — it's a design
   constraint. Link to the full article.
6. **CTA**: "Full deep-dive with code, threat model, and red-team results →
   manzambi.com/writing/secure-by-design-agentic"

**Tags:** #AISecurity #RedTeaming #OWASP #MCP #CyberSecurity #OpenSource


## Piece 2: Full Article (manzambi.com/writing)

**Title:** "Secure-By-Design Agentic AI: Building, Breaking, and Hardening
an AI Agent with MCP Tools"

**Target length:** 3,000-4,000 words

**Structure:**

### 1. Introduction — The Governance Gap (~400 words)
- The speed of agent adoption vs. the maturity of agent security
- NIST 81% stat, mcp-scan 43% stat
- Three frameworks converging: OWASP LLM Top 10 2025, NIST AI 600-1,
  CSA AICM + Agentic Scoping Matrix
- What this article covers and who it's for

### 2. Architecture — Defense in Depth (~600 words)
- Architecture diagram
- Four security layers explained:
  - Input Guard (OWASP LLM01)
  - Tool Authorizer (OWASP LLM06, CSA Scope 2)
  - Output Filter (OWASP LLM02, LLM05)
  - Audit Logger (NIST MEASURE 2.6)
- Why we built without a framework (LangChain abstraction problem)
- Why local inference matters for security testing

### 3. The Secure MCP Server — From Vulnerable to Hardened (~800 words)
- Side-by-side: vulnerable server vs. secure server
- Code walkthrough of each mitigation:
  - shell=True → argument lists
  - Raw paths → canonicalization + prefix check
  - No validation → strict allowlists
  - No limits → rate limiting
- OWASP MCP Guide alignment
- mcp-scan results comparison

### 4. Red Team Methodology — Three Layers of Attack (~600 words)
- Why breadth AND depth matter
- Layer 1: Broad scan (Garak + Promptfoo) — casting a wide net
- Layer 2: Compliance scan (OWASP preset + mcp-scan) — taxonomy coverage
- Layer 3: Adversarial (PyRIT Crescendo + TAP) — persistence testing
- How the orchestrator ties it together

### 5. Results — What Held and What Didn't (~800 words)
- Summary table with severity badges
- Analysis of each layer's findings
- What the secure design prevented
- What still got through (and why that's expected)
- Residual risks acknowledged

### 6. Lessons Learned (~400 words)
- System prompts are not security controls
- Allowlists > blocklists
- Deterministic enforcement > stochastic self-restraint
- Dual-layer audit logging catches discrepancies
- Red-teaming is a continuous process, not a one-time event

### 7. Conclusion & Resources (~200 words)
- Link to GitHub repo
- Links to all three frameworks
- Link to AI Red Team Orchestrator
- Newsletter signup CTA


## Publishing Plan

1. Write the full article first (for manzambi.com)
2. Compress the key insight into the LinkedIn piece
3. Cross-post a teaser to Twitter/X
4. Submit to relevant communities (r/netsec, Hacker News)

## Timeline (TBD)

- [ ] Run the full red team pipeline and collect results
- [ ] Write the full article
- [ ] Write the LinkedIn post
- [ ] Publish on manzambi.com
- [ ] Publish on LinkedIn
