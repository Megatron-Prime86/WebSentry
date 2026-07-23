"""Regex-based attack signatures.

Each entry maps an attack name to a list of compiled regex patterns. This is
intentionally signature-based (like a lightweight ModSecurity core rule set)
rather than a full parser — fast, easy to reason about, and easy to extend.

These are pattern-matching heuristics, not a guarantee of catching every
possible payload — a determined attacker can often find an encoding or
variant that slips past regex-based rules. That's true of real WAFs too;
it's one layer of defense, not the whole story.
"""

from __future__ import annotations

import re

_FLAGS = re.IGNORECASE

SQLI_PATTERNS = [
    re.compile(p, _FLAGS)
    for p in [
        r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",  # OR 1=1
        r"'\s*or\s*'.*'\s*=\s*'",  # ' or 'x'='x
        r"union\s+select",
        r"select\s+.+\s+from\s+",
        r"insert\s+into\s+",
        r"drop\s+table",
        r"information_schema",
        r"sleep\s*\(\s*\d+\s*\)",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
        r"--\s|--$|#\s*$|/\*.*\*/",  # SQL comment terminators
        r"load_file\s*\(",
        r"into\s+outfile",
        r";\s*(drop|delete|update|insert)\s",
    ]
]

XSS_PATTERNS = [
    re.compile(p, _FLAGS)
    for p in [
        r"<script[\s>]",
        r"</script>",
        r"javascript\s*:",
        r"on(error|load|click|mouseover|focus)\s*=",
        r"<img[^>]+onerror",
        r"<svg[^>]+onload",
        r"document\.cookie",
        r"<iframe[\s>]",
        r"eval\s*\(",
        r"<body[^>]+onload",
    ]
]

CMDI_PATTERNS = [
    re.compile(p, _FLAGS)
    for p in [
        r";\s*(ls|cat|whoami|id|pwd|rm|wget|curl|nc|bash|sh)\b",
        r"\|\s*(ls|cat|whoami|id|nc|bash|sh)\b",
        r"&&\s*(ls|cat|whoami|id|rm|wget|curl)\b",
        r"`[^`]+`",  # backtick command substitution
        r"\$\([^)]+\)",  # $(...) command substitution
        r"/bin/(ba)?sh",
        r"\brm\s+-rf\b",
    ]
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(p, _FLAGS)
    for p in [
        r"\.\./",
        r"\.\.\\",
        r"%2e%2e[/\\]",
        r"%2e%2e%2f",
        r"/etc/passwd",
        r"\\windows\\win\.ini",
        r"boot\.ini",
    ]
]

# Order matters only for which label wins if a payload matches multiple
# categories (rare) — first match returned by the engine wins.
RULES: list[tuple[str, list[re.Pattern]]] = [
    ("SQL Injection", SQLI_PATTERNS),
    ("Cross-Site Scripting (XSS)", XSS_PATTERNS),
    ("Command Injection", CMDI_PATTERNS),
    ("Path Traversal", PATH_TRAVERSAL_PATTERNS),
]
