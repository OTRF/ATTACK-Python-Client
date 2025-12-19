"""Cross-domain tactic query helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List

from stix2 import CompositeDataSource, Filter

from ...models import Tactic
from ...utils.stix import parse_stix_objects


class TacticsClient:
    """Tactic query helper class."""

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        parse_fn: Callable = parse_stix_objects
    ) -> None:
        """Initialize the client with a composite data source."""
        self._data_source = data_source
        self._parse_fn = parse_fn

    def get_tactics(self, *, stix_format: bool = True) -> List[Dict[str, Any]]:
        """Return tactics across all domains.

        Parameters
        ----------
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, parse to the
            `Tactic` Pydantic model.

        Returns
        -------
        list[dict[str, Any]]
            Tactic objects in the requested format.
        """
        all_tactics = self._data_source.query([Filter("type", "=", "x-mitre-tactic")])
        if not stix_format:
            all_tactics = self._parse_fn(all_tactics, Tactic)
        return all_tactics
