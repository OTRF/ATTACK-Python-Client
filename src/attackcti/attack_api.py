"""Backwards-compatible module."""

from .client import MitreAttackClient
from .client import MitreAttackClient as attack_client

__all__ = ["MitreAttackClient", "attack_client"]
