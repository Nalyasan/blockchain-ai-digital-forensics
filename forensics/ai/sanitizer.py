"""On-Chain Input Sanitizer & Prompt Injection Isolation (Milestone 3 / T11).

Provides defensive sanitization and isolation for untrusted on-chain data:
- Strips ASCII control characters (< 32 except newline) and DEL.
- Removes hidden/zero-width Unicode (U+200B, U+FEFF, U+200C, U+200D, etc.).
- Removes bidirectional text overrides (U+202E, U+202A-202D, U+2066-2069).
- Normalizes text via NFKC to defeat visual/compatibility obfuscation.
- Escapes XML/HTML delimiters (<, >, &) to prevent delimiter breakout.
- Truncates raw content to max_len (default 128 characters).
- Wraps untrusted text securely within `<untrusted_onchain_data>...</untrusted_onchain_data>`.
- Detects prompt injection attempts against system instructions, tools, or schemas.
- Invariant: Zero mutating statements (G5-02).
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any


# Zero-width, invisible formatting, and non-printable characters
HIDDEN_UNICODE_CODEPOINTS = {
    0x200B,  # ZERO WIDTH SPACE
    0x200C,  # ZERO WIDTH NON-JOINER
    0x200D,  # ZERO WIDTH JOINER
    0x2060,  # WORD JOINER
    0xFEFF,  # ZERO WIDTH NO-BREAK SPACE / BYTE ORDER MARK
    0x180E,  # MONGOLIAN VOWEL SEPARATOR
    0x00AD,  # SOFT HYPHEN
}

# Bidirectional overrides and directional control codepoints
BIDI_OVERRIDE_CODEPOINTS = {
    0x202A,  # LEFT-TO-RIGHT EMBEDDING
    0x202B,  # RIGHT-TO-LEFT EMBEDDING
    0x202C,  # POP DIRECTIONAL FORMATTING
    0x202D,  # LEFT-TO-RIGHT OVERRIDE
    0x202E,  # RIGHT-TO-LEFT OVERRIDE
    0x2066,  # LEFT-TO-RIGHT ISOLATE
    0x2067,  # RIGHT-TO-LEFT ISOLATE
    0x2068,  # FIRST STRONG ISOLATE
    0x2069,  # POP DIRECTIONAL ISOLATE
    0x200E,  # LEFT-TO-RIGHT MARK
    0x200F,  # RIGHT-TO-LEFT MARK
    0x061C,  # ARABIC LETTER MARK
}

# Compiled regex patterns for prompt injection attack signatures
PROMPT_INJECTION_PATTERNS = [
    # 1. Instruction overrides & Amnesia triggers
    re.compile(
        r"\bignore\s+(?:all\s+)?(?:previous|prior|above|system|existing)\s+(?:instructions|prompts|directions|rules|commands)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdisregard\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|directions|rules)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bforget\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bdo\s+not\s+follow\s+(?:previous|prior|system|any)\s+(?:instructions|rules)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\boverride\s+(?:system|instructions|prompt|rules|safety|guardrails)\b",
        re.IGNORECASE,
    ),
    # 2. System prompt manipulation & Persona hijacking
    re.compile(r"\bsystem\s*prompt\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\s+(?:an?|the|a\s+new)\b", re.IGNORECASE),
    re.compile(r"\bnew\s+role\s*:", re.IGNORECASE),
    re.compile(r"\bact\s+as\s+(?:an?|a\s+helpful|a\s+different|dan)\b", re.IGNORECASE),
    re.compile(r"\bdan\s+mode\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
    re.compile(r"\bdeveloper\s+mode\b", re.IGNORECASE),
    re.compile(
        r"\bbypass\s+(?:safety|security|guardrails|validation|filters|rules)\b",
        re.IGNORECASE,
    ),
    # 3. Delimiter breakout & Tag forgery
    re.compile(r"</?\s*untrusted_onchain_data\s*>", re.IGNORECASE),
    re.compile(r"</?\s*system\s*>", re.IGNORECASE),
    re.compile(r"\[/?INST\]", re.IGNORECASE),
    re.compile(r"<\|im_(?:start|end)\|>", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]", re.IGNORECASE),
    # 4. Tool alteration & Shell / Command execution attempts
    re.compile(
        r"\bexecute\s+(?:shell|bash|cmd|powershell|command|code|script|sql)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\brun\s+(?:command|script|shell|code)\b", re.IGNORECASE),
    re.compile(r"\b(?:call_tool|tool_call|unauthorized_tool|tool_bash)\b", re.IGNORECASE),
    re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
    re.compile(r"\bdelete\s+from\b", re.IGNORECASE),
    re.compile(r"\brm\s+-rf\b", re.IGNORECASE),
    re.compile(r"\b(?:subprocess|os\.system|exec\(|eval\()\b", re.IGNORECASE),
    # 5. Schema manipulation & Hallucinated facts injection
    re.compile(r"\"?observed_facts\"?\s*:", re.IGNORECASE),
    re.compile(r"\"?tx_hash\"?\s*:", re.IGNORECASE),
    re.compile(
        r"\boutput\s+only\s+(?:the\s+following\s+)?json\b", re.IGNORECASE
    ),
    re.compile(r"\breturn\s+json\s+with\s+case_id\b", re.IGNORECASE),
]


def detect_prompt_injection(text: str) -> bool:
    """Evaluates whether the given text contains prompt injection attack patterns.
    
    Used for flagging and forensic auditing (records injection_detected = 1).
    Does not substitute for structural containment (tag wrapping and tool whitelists).
    """
    if not text:
        return False
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def _clean_unicode_and_controls(text: str) -> str:
    """Strips forbidden control characters, hidden Unicode, and bidirectional overrides."""
    cleaned_chars: list[str] = []
    for c in text:
        cp = ord(c)
        # Preserve standard newline
        if c == "\n":
            cleaned_chars.append(c)
            continue

        # Strip ASCII control characters < 32 and DEL (127)
        if cp < 32 or cp == 127:
            continue

        # Strip specific hidden zero-width and bidi override code points
        if cp in HIDDEN_UNICODE_CODEPOINTS or cp in BIDI_OVERRIDE_CODEPOINTS:
            continue

        # Strip Unicode Tag block (U+E0000 to U+E007F) used for steganographic injection
        if 0xE0000 <= cp <= 0xE007F:
            continue

        # Strip general Unicode 'Cf' (Other, format) and 'Cc' (Other, control) categories
        cat = unicodedata.category(c)
        if cat in ("Cf", "Cc"):
            continue

        cleaned_chars.append(c)

    return "".join(cleaned_chars)


def escape_untrusted_delimiters(text: str) -> str:
    """Escapes XML/HTML delimiters (&, <, >) to prevent container breakout."""
    text = text.replace("&", "&amp;")
    text = text.replace("<", "&lt;")
    text = text.replace(">", "&gt;")
    return text


def sanitize_onchain_string(raw_val: str, max_len: int = 128) -> tuple[str, bool]:
    """Sanitizes untrusted on-chain text, isolates under XML tags, and detects injection attacks.
    
    Processing Pipeline:
    1. Type coercion to string (handles None, numbers, bytes safely).
    2. NFKC Unicode normalization to defeat fullwidth/homoglyph obfuscation.
    3. Stripping of ASCII controls (< 32 except newline), zero-width characters,
       and bidirectional text overrides (U+202E, U+FEFF, U+200B).
    4. Evaluation against compiled prompt injection attack patterns.
    5. Truncation to max_len (default 128 characters).
    6. Delimiter escaping (& -> &amp;, < -> &lt;, > -> &gt;) to prevent breakout.
    7. Wrapping securely within `<untrusted_onchain_data>...</untrusted_onchain_data>`.
    """
    if max_len < 0:
        raise ValueError(f"max_len must be non-negative, got {max_len}")

    if raw_val is None:
        raw_str = ""
    elif isinstance(raw_val, bytes):
        raw_str = raw_val.decode("utf-8", errors="replace")
    elif not isinstance(raw_val, str):
        raw_str = str(raw_val)
    else:
        raw_str = raw_val

    # 1. NFKC normalization: resolves fullwidth chars (e.g. Ｉｇｎｏｒｅ -> Ignore)
    normalized = unicodedata.normalize("NFKC", raw_str)

    # 2. Strip controls, zero-width, and bidi overrides
    cleaned = _clean_unicode_and_controls(normalized)

    # 3. Prompt injection detection on cleaned text (before truncation to avoid evasion via padding)
    injection_detected = detect_prompt_injection(cleaned)

    # 4. Truncate to max_len
    truncated = cleaned[:max_len]

    # 5. Escape delimiters to prevent container breakout
    escaped = escape_untrusted_delimiters(truncated)

    # 6. Encapsulate in isolation tags
    wrapped = f"<untrusted_onchain_data>{escaped}</untrusted_onchain_data>"

    return wrapped, injection_detected


def sanitize_onchain_dict(
    data: dict[str, Any], max_len: int = 128
) -> tuple[dict[str, Any], bool]:
    """Recursively sanitizes string fields in dictionaries (e.g. tool results, alerts)."""
    sanitized: dict[str, Any] = {}
    any_injection = False

    for k, v in data.items():
        if isinstance(v, str):
            wrapped, detected = sanitize_onchain_string(v, max_len=max_len)
            sanitized[k] = wrapped
            if detected:
                any_injection = True
        elif isinstance(v, dict):
            sub_dict, sub_detected = sanitize_onchain_dict(v, max_len=max_len)
            sanitized[k] = sub_dict
            if sub_detected:
                any_injection = True
        elif isinstance(v, list):
            sub_list, sub_detected = sanitize_onchain_list(v, max_len=max_len)
            sanitized[k] = sub_list
            if sub_detected:
                any_injection = True
        else:
            sanitized[k] = v

    return sanitized, any_injection


def sanitize_onchain_list(
    items: list[Any], max_len: int = 128
) -> tuple[list[Any], bool]:
    """Recursively sanitizes string items in lists."""
    sanitized: list[Any] = []
    any_injection = False

    for item in items:
        if isinstance(item, str):
            wrapped, detected = sanitize_onchain_string(item, max_len=max_len)
            sanitized.append(wrapped)
            if detected:
                any_injection = True
        elif isinstance(item, dict):
            sub_dict, sub_detected = sanitize_onchain_dict(item, max_len=max_len)
            sanitized.append(sub_dict)
            if sub_detected:
                any_injection = True
        elif isinstance(item, list):
            sub_list, sub_detected = sanitize_onchain_list(item, max_len=max_len)
            sanitized.append(sub_list)
            if sub_detected:
                any_injection = True
        else:
            sanitized.append(item)

    return sanitized, any_injection
