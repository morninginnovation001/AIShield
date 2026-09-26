"""
Defense base class for prompt injection research defenses.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional


class DefenseBase:
    """Base class for all defense mechanisms."""

    def __init__(self, name: str, description: str, defense_type: str, enabled: bool = False):
        self.name = name
        self.description = description
        self.defense_type = defense_type
        self.enabled = enabled

        # Stats
        self.applied_count = 0
        self.blocked_count = 0
        self.logger = logging.getLogger(__name__)

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False

    def is_enabled(self) -> bool:
        return self.enabled

    def get_stats(self) -> Dict[str, Any]:
        total = self.applied_count
        return {
            "name": self.name,
            "type": self.defense_type,
            "enabled": self.enabled,
            "applied": total,
            "blocked": self.blocked_count,
        }

    # Subclasses override the relevant apply/validate methods below.
    # They should increment applied_count and blocked_count appropriately.
