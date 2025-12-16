"""Backwards-compatible module."""

from .client import AttackClient, AttackClient as attack_client

__all__ = ["AttackClient", "attack_client"]

