"""Cross-domain analytics query helpers."""

from __future__ import annotations

from typing import Any, Callable, Iterable

from stix2 import CompositeDataSource, Filter

from ...models import Analytic as AnalyticModel
from ...utils.stix import (
    as_dict,
    parse_stix_objects,
    query_stix_objects_by_ids,
    remove_revoked_deprecated,
)


class AnalyticsClient:
    """Cross-domain analytics client (COMPOSITE_DS-backed)."""

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        remove_fn: Callable = remove_revoked_deprecated,
        parse_fn: Callable = parse_stix_objects,
    ) -> None:
        """Initialize the client with a data source and helper callbacks."""
        self._data_source = data_source
        self._remove_fn = remove_fn
        self._parse_fn = parse_fn

    def get_analytics(self, *, stix_format: bool = True) -> list[dict[str, Any]]:
        """Return all analytic objects."""
        analytics = self._data_source.query(Filter("type", "=", "x-mitre-analytic"))
        if not stix_format:
            return self._parse_fn(analytics, AnalyticModel)
        return [as_dict(a) for a in analytics]
    
    def get_analytics_by_ids(self, ids: Iterable[str]) -> dict[str, dict[str, Any]]:
        """Return analytics keyed by their STIX id."""
        analytics_dict: dict[str, dict[str, Any]] = {}
        analytic_ids = {aid for aid in ids if isinstance(aid, str) and aid}
        if not analytic_ids:
            return analytics_dict

        analytics = query_stix_objects_by_ids(
            data_source=self._data_source,
            stix_type="x-mitre-analytic",
            ids=analytic_ids
        )
        for analytic in analytics:
            analytic_dict = as_dict(analytic)
            analytic_id = analytic_dict.get("id")
            if not isinstance(analytic_id, str) or not analytic_id:
                continue
            log_sources = analytic_dict.get("x_mitre_log_source_references") or []
            analytic_dict["x_attackcti_log_sources"] = [ls for ls in log_sources if isinstance(ls, dict)]
            analytics_dict[analytic_id] = analytic_dict
        return analytics_dict
