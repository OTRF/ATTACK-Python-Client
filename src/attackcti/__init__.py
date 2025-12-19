"""attackcti package.

This package exposes a small, stable public surface:
- `MitreAttackClient`: main client class
- `attack_client`: backwards-compatible alias
"""

from __future__ import annotations

from importlib import metadata
from typing import TYPE_CHECKING, Any

__all__ = ["AttackClient", "attack_client", "__version__"]

try:
    __version__ = metadata.version("attackcti")
except metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "0.0.0"

if TYPE_CHECKING:  # pragma: no cover
    from .client import MitreAttackClient as AttackClient


def __getattr__(name: str) -> Any:  # PEP 562
    """Lazily expose selected public symbols."""
    if name in {"MitreAttackClient", "attack_client"}:
        from .client import MitreAttackClient

        return MitreAttackClient
    raise AttributeError(name)
