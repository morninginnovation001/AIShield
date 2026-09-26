"""Attacks benchmark package for AIShield."""

from .attack_suite import (
    AttackCase,
    ATTACK_SUITE,
    get_attack_suite,
    get_attacks_by_category,
    get_suite_statistics,
)

__all__ = [
    "AttackCase",
    "ATTACK_SUITE",
    "get_attack_suite",
    "get_attacks_by_category",
    "get_suite_statistics",
]
