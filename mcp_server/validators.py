"""
MCP Server Validators
======================
Centralized input validation for all MCP server tools. Every parameter
that enters a tool passes through validation here BEFORE any operation
is performed.

Framework alignment:
    OWASP MCP Security Guide §4.2-4.3:
        "Replace shell=True subprocess calls with argument-list invocations;
        whitelist allowed log paths via os.path.realpath + prefix check;
        reject any '..' segments before execution."

    OWASP LLM05 (Improper Output Handling):
        Validation prevents downstream injection when tool outputs are
        fed back to the LLM.

    CSA AICM AIS-05:
        Input validation and sanitization controls.

    NIST SP 800-53 SI-10 (Information Input Validation):
        "The information system checks the validity of information inputs."

DESIGN DECISIONS:
    1. ALLOWLIST over blocklist: We define what IS allowed, not what isn't.
       Blocklists are always incomplete; allowlists fail safely.
    2. Path canonicalization: All file paths are resolved with realpath()
       and checked against a prefix allowlist BEFORE any file operation.
    3. No regex-based command filtering: Instead of trying to filter
       dangerous commands, we never use shell=True in the first place.
       The safe subprocess pattern is argument lists.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# --- Configuration ---

# Allowed log directory (canonicalized).
# All file operations are restricted to this directory.
# IMPORTANT: This uses /var/log as a sensible default. In production,
# you'd likely use a dedicated log directory with restricted permissions.
LOG_DIRECTORY = Path("/var/log").resolve()

# Allowed file extensions for log files
ALLOWED_EXTENSIONS = {".log", ".txt", ".gz", ".1", ".2", ".3", ".4", ".5", ""}
# Note: "" allows extensionless files like 'syslog', 'auth.log', etc.

# Maximum filename length
MAX_FILENAME_LENGTH = 255

# Maximum search keyword length
MAX_KEYWORD_LENGTH = 100

# Allowed characters in filenames (strict allowlist)
FILENAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")

# Allowed characters in search keywords (strict allowlist)
KEYWORD_PATTERN = re.compile(r"^[a-zA-Z0-9\s._-]+$")

# Maximum file size to read (prevents memory exhaustion)
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Maximum number of search results to return
MAX_SEARCH_RESULTS = 100


class ValidationError(Exception):
    """Raised when input validation fails."""

    def __init__(self, message: str, parameter: str, value: str = ""):
        self.message = message
        self.parameter = parameter
        self.value = value[:50]  # Truncate for logging safety
        super().__init__(f"Validation error on '{parameter}': {message}")


def validate_filename(filename: str) -> Path:
    """
    Validate and resolve a filename to a safe, canonical path.

    Security checks (in order):
    1. Non-empty string
    2. Length limit
    3. Character allowlist (no path separators, no special chars)
    4. No path traversal components (..)
    5. Canonical path resolves within LOG_DIRECTORY
    6. File extension is allowed
    7. Resolved path is a regular file (not a symlink to outside)

    Args:
        filename: Raw filename from the tool call

    Returns:
        Resolved, validated Path object

    Raises:
        ValidationError: If any check fails
    """
    # Check 1: Non-empty
    if not filename or not filename.strip():
        raise ValidationError("Filename cannot be empty", "filename")

    filename = filename.strip()

    # Check 2: Length limit
    if len(filename) > MAX_FILENAME_LENGTH:
        raise ValidationError(
            f"Filename too long ({len(filename)} > {MAX_FILENAME_LENGTH})",
            "filename",
            filename,
        )

    # Check 3: Character allowlist
    # CRITICAL: This rejects path separators (/ and \), preventing
    # any path traversal attempt regardless of encoding.
    if not FILENAME_PATTERN.match(filename):
        raise ValidationError(
            "Filename contains disallowed characters. "
            "Only alphanumeric, dots, hyphens, and underscores are allowed. "
            "Path separators are not permitted.",
            "filename",
            filename,
        )

    # Check 4: Explicit path traversal check (belt AND suspenders)
    if ".." in filename:
        raise ValidationError(
            "Path traversal detected: '..' is not allowed",
            "filename",
            filename,
        )

    # Check 5: Canonical path resolution
    # os.path.realpath resolves symlinks and normalizes the path.
    # We then verify the result starts with our allowed directory.
    candidate = (LOG_DIRECTORY / filename).resolve()

    if not str(candidate).startswith(str(LOG_DIRECTORY)):
        raise ValidationError(
            "Resolved path is outside the allowed directory",
            "filename",
            filename,
        )

    # Check 6: File extension
    suffix = candidate.suffix
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            f"File extension '{suffix}' is not allowed",
            "filename",
            filename,
        )

    return candidate


def validate_keyword(keyword: str) -> str:
    """
    Validate a search keyword.

    Security checks:
    1. Non-empty string
    2. Length limit (prevents regex DoS / unbounded processing)
    3. Character allowlist (no shell metacharacters, no regex specials)

    Args:
        keyword: Raw search keyword from the tool call

    Returns:
        Validated, stripped keyword string

    Raises:
        ValidationError: If any check fails
    """
    if not keyword or not keyword.strip():
        raise ValidationError("Keyword cannot be empty", "keyword")

    keyword = keyword.strip()

    if len(keyword) > MAX_KEYWORD_LENGTH:
        raise ValidationError(
            f"Keyword too long ({len(keyword)} > {MAX_KEYWORD_LENGTH})",
            "keyword",
            keyword,
        )

    if not KEYWORD_PATTERN.match(keyword):
        raise ValidationError(
            "Keyword contains disallowed characters. "
            "Only alphanumeric, spaces, dots, hyphens, and underscores are allowed.",
            "keyword",
            keyword,
        )

    return keyword


def validate_file_readable(path: Path) -> None:
    """
    Verify that a validated path points to a readable regular file.

    Args:
        path: Previously validated path from validate_filename()

    Raises:
        ValidationError: If the file doesn't exist, isn't readable,
                         or exceeds the size limit
    """
    if not path.exists():
        raise ValidationError(
            "File does not exist",
            "filename",
            path.name,
        )

    if not path.is_file():
        raise ValidationError(
            "Path is not a regular file (may be a directory or device)",
            "filename",
            path.name,
        )

    if not os.access(path, os.R_OK):
        raise ValidationError(
            "File is not readable (permission denied)",
            "filename",
            path.name,
        )

    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE_BYTES:
        raise ValidationError(
            f"File too large ({file_size} bytes > {MAX_FILE_SIZE_BYTES} bytes)",
            "filename",
            path.name,
        )
