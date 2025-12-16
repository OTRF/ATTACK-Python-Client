"""Backwards-compatible module."""

from .client import AttackClient, AttackClient as attack_client  # noqa: F401

__all__ = ["AttackClient", "attack_client"]
