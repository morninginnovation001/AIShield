"""
Input sanitization defenses.

Provides lightweight regex-based filtering and detection for injection patterns
and jailbreak/role-play indicators.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from .defense_base import DefenseBase


class InputSanitizer(DefenseBase):
    """Regex-based input sanitization and detection."""

    def __init__(self, config: Optional[Dict[str, Any]] = None, enabled: bool = False):
        super().__init__(
            name="Input Sanitization",
            description="Regex filtering and content checks for malicious input",
            defense_type="input_sanitization",
            enabled=enabled,
        )
        config = config or {}

        patterns = (config.get("patterns_to_filter") or [])
        self.patterns: List[re.Pattern] = [re.compile(p, re.IGNORECASE) for p in patterns]

        moderation = config.get("content_moderation") or {}
        self.detect_roleplay = bool(moderation.get("detect_roleplay", True))
        self.detect_jailbreak = bool(moderation.get("detect_jailbreak", True))
        self.detect_injection_keywords = bool(moderation.get("detect_injection_keywords", True))

        validation = config.get("query_validation") or {}
        self.max_length = int(validation.get("max_length", 5000))
        self.require_alphanumeric = bool(validation.get("require_alphanumeric", False))
        self.block_special_chars = bool(validation.get("block_special_chars", False))

    def sanitize(self, query: str) -> Tuple[str, Optional[str]]:
        """Apply sanitization rules; returns sanitized query and optional reason."""
        reason_parts: List[str] = []
        original = query

        # Length cap
        if len(query) > self.max_length:
            query = query[: self.max_length]
            reason_parts.append("trimmed_excess_length")

        # Pattern filtering (remove suspicious segments)
        for pat in self.patterns:
            if pat.search(query):
                query = pat.sub(" ", query)
                reason_parts.append(f"filtered:{pat.pattern}")

        # Optional character policies
        if self.require_alphanumeric and not re.search(r"[a-zA-Z0-9]", query):
            reason_parts.append("no_alphanumeric")

        if self.block_special_chars:
            # allow punctuation in a conservative manner
            query = re.sub(r"[^a-zA-Z0-9\s,.?;:'\-_/()\[\]{}]", " ", query)
            reason_parts.append("blocked_special_chars")

        # Detection flags (do not block here; used for analytics/policies)
        lower = original.lower()
        if self.detect_roleplay and ("you are now" in lower or "pretend you are" in lower):
            reason_parts.append("roleplay_detected")
        if self.detect_jailbreak and ("ignore instructions" in lower or "override" in lower):
            reason_parts.append("jailbreak_detected")
        if self.detect_injection_keywords and ("system:" in lower or "</context>" in lower):
            reason_parts.append("injection_keywords")

        reason = ",".join(reason_parts) if reason_parts else None
        return query, reason

    def apply(self, query: str) -> Tuple[bool, str, Optional[str]]:
        if not self.enabled:
            return True, query, None
        self.applied_count += 1
        sanitized, reason = self.sanitize(query)
        blocked = False  # In this research setup, we sanitize but do not hard-block
        if blocked:
            self.blocked_count += 1
        return not blocked, sanitized, reason

