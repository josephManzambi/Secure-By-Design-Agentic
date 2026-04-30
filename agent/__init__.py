"""
Secure Agent Layer
==================
Defense-in-depth AI agent with input validation, tool authorization,
output filtering, and audit logging.

Framework alignment:
    - OWASP LLM01 (Prompt Injection): Input Guard
    - OWASP LLM02 (Sensitive Info Disclosure): Output Filter
    - OWASP LLM05 (Improper Output Handling): Output Filter
    - OWASP LLM06 (Excessive Agency): Tool Authorizer
    - OWASP LLM07 (System Prompt Leakage): Config (no secrets in prompt)
    - NIST AI 600-1 §5.1-5.7: Multiple layers
    - CSA AICM AIS-04 through AIS-14: Multiple controls
"""
