"""
Input Guard
===========
Validates and sanitizes user input BEFORE it reaches the LLM. This is the
first line of defense against prompt injection and related attacks.

Framework alignment:
    OWASP LLM01 (Prompt Injection):
        "Prompt injection vulnerabilities are possible due to the nature of
        generative AI. Given the stochastic influence at the heart of the way
        models work, it is unclear if there are fool-proof methods of
        prevention for prompt injection."
        — OWASP Top 10 for LLMs 2025

        This module implements:
        - Input length validation (prevents resource exhaustion, LLM10)
        - Known injection pattern detection (heuristic, not fool-proof)
        - Encoding attack detection (base64, unicode, hex obfuscation)
        - Structured input logging for forensic analysis

    NIST AI 600-1 §5.1:
        "Define sensitive categories and construct rules for identifying
        and handling such content. Apply semantic filters and use
        string-checking to scan for non-allowed content."

    CSA AICM AIS-04:
        Input validation controls for AI system interfaces.

IMPORTANT NOTE:
    Input validation is a DEFENSE-IN-DEPTH measure. It cannot prevent all
    prompt injection attacks. The LLM will still process adversarial inputs
    that pass these checks. That's why we have additional layers:
    tool_authorizer.py (controls what the LLM can DO) and output_filter.py
    (controls what the user SEES).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Classification of input risk."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    BLOCKED = "blocked"


@dataclass
class InputAnalysis:
    """Result of input validation."""

    risk_level: RiskLevel
    original_input: str
    sanitized_input: str
    flags: list[str]

    @property
    def is_allowed(self) -> bool:
        return self.risk_level != RiskLevel.BLOCKED


# --- Known injection patterns ---
# These are HEURISTIC detections. They catch obvious attacks but will not
# catch sophisticated adversarial prompts. That's expected — no input
# filter is a complete solution for prompt injection (OWASP LLM01).

INJECTION_PATTERNS: list[tuple[str, str, RiskLevel]] = [
    # Direct instruction override attempts
    (
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        "Instruction override attempt detected",
        RiskLevel.BLOCKED,
    ),
    (
        r"(?i)disregard\s+(all\s+)?prior\s+(instructions|context|rules)",
        "Instruction override attempt detected",
        RiskLevel.BLOCKED,
    ),
    (
        r"(?i)forget\s+(everything|all|your)\s+(you|instructions|rules)",
        "Instruction override attempt detected",
        RiskLevel.BLOCKED,
    ),
    # System prompt extraction
    (
        r"(?i)(print|show|reveal|display|output|repeat)\s+(your|the)\s+(full\s+)?(system\s+)?prompt",
        "System prompt extraction attempt",
        RiskLevel.BLOCKED,
    ),
    (
        r"(?i)what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
        "System prompt extraction attempt",
        RiskLevel.SUSPICIOUS,
    ),
    # Role hijacking
    (
        r"(?i)you\s+are\s+now\s+(a|an|the)",
        "Role hijacking attempt",
        RiskLevel.SUSPICIOUS,
    ),
    (
        r"(?i)(pretend|act|behave)\s+(like|as if)\s+you",
        "Role hijacking attempt",
        RiskLevel.SUSPICIOUS,
    ),
    # Delimiter injection (trying to break out of user message context)
    (
        r"(?i)<\s*/?\s*(system|assistant|user|tool)\s*>",
        "Delimiter injection attempt",
        RiskLevel.BLOCKED,
    ),
    (
        r"(?i)\[/?INST\]",
        "Delimiter injection attempt",
        RiskLevel.BLOCKED,
    ),
    # Shell command injection via tool parameters
    (
        r"(?:;|\||&&|\$\(|`)\s*(cat|ls|rm|wget|curl|bash|sh|python|nc)\b",
        "Shell injection pattern in input",
        RiskLevel.BLOCKED,
    ),
    # Path traversal
    (
        r"\.\./\.\.",
        "Path traversal pattern detected",
        RiskLevel.BLOCKED,
    ),
]


def _check_encoding_attacks(text: str) -> list[tuple[str, RiskLevel]]:
    """
    Detect inputs that use encoding to obfuscate malicious content.

    OWASP LLM01 specifically calls out encoding-based attacks:
    base64, unicode escaping, and hex encoding are common evasion
    strategies for prompt injection.
    """
    flags = []

    # Check for base64-encoded content that might contain instructions
    # Heuristic: long sequences of base64 characters are suspicious
    b64_pattern = re.findall(r"[A-Za-z0-9+/]{40,}={0,2}", text)
    for match in b64_pattern:
        try:
            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
            # Check if the decoded content contains injection patterns
            if any(
                re.search(pattern, decoded, re.IGNORECASE)
                for pattern, _, _ in INJECTION_PATTERNS
            ):
                flags.append(
                    ("Base64-encoded injection pattern detected", RiskLevel.BLOCKED)
                )
                break
        except Exception:
            pass

    # Check for excessive unicode escape sequences (obfuscation)
    unicode_escapes = len(re.findall(r"\\u[0-9a-fA-F]{4}", text))
    if unicode_escapes > 10:
        flags.append(
            ("Excessive unicode escape sequences (possible obfuscation)", RiskLevel.SUSPICIOUS)
        )

    # Check for hex-encoded content
    hex_sequences = len(re.findall(r"\\x[0-9a-fA-F]{2}", text))
    if hex_sequences > 10:
        flags.append(
            ("Excessive hex escape sequences (possible obfuscation)", RiskLevel.SUSPICIOUS)
        )

    return flags


def _check_length(text: str, max_length: int) -> list[tuple[str, RiskLevel]]:
    """
    Enforce input length limits.

    OWASP LLM10 (Unbounded Consumption):
        "An attacker submits unusually large prompts that overload memory
        and CPU, slowing down or crashing the system."

    NIST AI 600-1 §5.10:
        Resource consumption controls for generative AI systems.
    """
    flags = []
    if len(text) > max_length:
        flags.append(
            (
                f"Input exceeds maximum length ({len(text)} > {max_length} chars)",
                RiskLevel.BLOCKED,
            )
        )
    elif len(text) > max_length * 0.8:
        flags.append(
            (
                f"Input approaching maximum length ({len(text)}/{max_length} chars)",
                RiskLevel.SUSPICIOUS,
            )
        )
    return flags


def validate_input(text: str, max_length: int = 4096) -> InputAnalysis:
    """
    Validate and analyze user input. Returns an InputAnalysis with risk
    classification and any flags raised.

    This function does NOT modify the input (sanitization is separate).
    It classifies risk so the agent can make informed decisions.

    Args:
        text: Raw user input
        max_length: Maximum allowed input length (OWASP LLM10)

    Returns:
        InputAnalysis with risk level, flags, and the original input
    """
    flags: list[str] = []
    highest_risk = RiskLevel.SAFE

    def _escalate(level: RiskLevel, message: str) -> None:
        nonlocal highest_risk
        flags.append(message)
        if level == RiskLevel.BLOCKED or (
            level == RiskLevel.SUSPICIOUS and highest_risk == RiskLevel.SAFE
        ):
            highest_risk = level

    # 1. Length check
    for message, level in _check_length(text, max_length):
        _escalate(level, message)

    # 2. Known injection patterns
    for pattern, message, level in INJECTION_PATTERNS:
        if re.search(pattern, text):
            _escalate(level, message)

    # 3. Encoding attacks
    for message, level in _check_encoding_attacks(text):
        _escalate(level, message)

    # 4. Empty or whitespace-only input
    if not text.strip():
        _escalate(RiskLevel.BLOCKED, "Empty or whitespace-only input")

    return InputAnalysis(
        risk_level=highest_risk,
        original_input=text,
        sanitized_input=text.strip(),
        flags=flags,
    )
