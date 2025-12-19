"""Cross-domain detection-model query helpers."""

from __future__ import annotations

from logging import getLogger
from typing import Any, Callable, Iterable

from stix2 import CompositeDataSource, Filter
from stix2.utils import get_type_from_id

from ...models import Analytic as AnalyticModel
from ...models import DetectionStrategy as DetectionStrategyModel
from ...utils.stix import (
    as_dict,
    parse_stix_objects,
    query_stix_objects_by_ids,
    remove_revoked_deprecated,
    stix_id,
)

logger = getLogger(__name__)

class DetectionsClient:
    """Cross-domain detections client (COMPOSITE_DS-backed).

    Parameters
    ----------
    data_source
        Composite STIX2 data source (e.g., `CompositeDataSource`).
    """

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        remove_fn: Callable = remove_revoked_deprecated,
        parse_fn: Callable = parse_stix_objects,
        get_analytics_by_ids_fn: Callable[..., Any] | None = None,
        get_data_components_by_ids_fn: Callable[..., Any] | None = None,
        
    ) -> None:
        """Initialize the client with a composite data source and model map."""
        self._data_source = data_source
        self._remove_fn = remove_fn
        self._parse_fn = parse_fn
        self._get_analytics_by_ids_fn = get_analytics_by_ids_fn
        self._get_data_components_by_ids_fn = get_data_components_by_ids_fn

    def set_get_analytics_by_ids_fn(self, fn: Callable[..., Any] | None) -> None:
        """Set or update the injected get_analytics_by_ids callback."""
        self._get_analytics_by_ids_fn = fn
    
    def set_get_data_components_by_ids_fn(self, fn: Callable[..., Any] | None) -> None:
        """Set or update the injected get_data_components_by_ids callback."""
        self._get_data_components_by_ids_fn = fn

    def _detects_relationships(self) -> list[dict[str, Any]]:
        """Return non-revoked `detects` relationships as dictionaries."""
        logger.debug("Querying TAXII for non-revoked detects relationships")
        rels = self._data_source.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "detects"),
            ]
        )
        rels = self._remove_fn(rels)
        logger.debug("Detected %d non-revoked detects relationships", len(rels))
        return [as_dict(r) for r in rels]

    def _strategy_ids_by_technique(self, technique_ids: Iterable[str]) -> dict[str, set[str]]:
        """Group detection strategy ids that detect the provided techniques."""
        detects = self._detects_relationships()
        mapping: dict[str, set[str]] = {}
        for rel in detects:
            source_ref = rel.get("source_ref")
            target_ref = rel.get("target_ref")
            if not (isinstance(source_ref, str) and isinstance(target_ref, str)):
                continue
            if target_ref not in technique_ids:
                continue
            if get_type_from_id(source_ref) != "x-mitre-detection-strategy":
                continue
            mapping.setdefault(target_ref, set()).add(source_ref)
        return mapping

    def get_detection_context_for_techniques(self, technique_ids: Iterable[str]) -> dict[str, list[dict[str, Any]]]:
        """Return detection strategies (with analytics/log-sources) grouped by technique."""
        strategy_ids_by_technique = self._strategy_ids_by_technique(technique_ids)
        if not strategy_ids_by_technique:
            return {}

        all_strategy_ids = {sid for sids in strategy_ids_by_technique.values() for sid in sids}
        logger.debug("Found %d detection strategies for %d techniques", len(all_strategy_ids), len(strategy_ids_by_technique))
        if not all_strategy_ids:
            return {}

        strategies = query_stix_objects_by_ids(
            data_source=self._data_source,
            stix_type="x-mitre-detection-strategy",
            ids = all_strategy_ids
        )
        strategies_dicts = [as_dict(s) for s in strategies]
        strategies_by_id = {s.get("id"): s for s in strategies_dicts if isinstance(s.get("id"), str)}
        analytic_ids = {
            ref
            for strategy in strategies_dicts
            for ref in strategy.get("x_mitre_analytic_refs") or []
            if isinstance(ref, str) and ref
        }
        logger.debug("Collected %d analytic IDs", len(analytic_ids))
        if callable(self._get_analytics_by_ids_fn):
            analytics_by_id = self._get_analytics_by_ids_fn(analytic_ids)
        else:
            # Fallback: query analytics directly when not injected (standalone client usage).
            analytics = query_stix_objects_by_ids(
                data_source=self._data_source,
                stix_type="x-mitre-analytic",
                ids=analytic_ids,
            )
            analytics_by_id = {}
            for analytic in analytics:
                analytic_dict = as_dict(analytic)
                analytic_id = analytic_dict.get("id")
                if not isinstance(analytic_id, str) or not analytic_id:
                    continue
                log_sources = analytic_dict.get("x_mitre_log_source_references") or []
                analytic_dict["x_attackcti_log_sources"] = [ls for ls in log_sources if isinstance(ls, dict)]
                analytics_by_id[analytic_id] = analytic_dict

        context: dict[str, list[dict[str, Any]]] = {}
        for tid, sids in strategy_ids_by_technique.items():
            strategy_objs: list[dict[str, Any]] = []
            for sid in sorted(sids):
                strategy = strategies_by_id.get(sid)
                if not isinstance(strategy, dict):
                    continue
                strategy_copy = dict(strategy)
                analytics: list[dict[str, Any]] = []
                for ref in strategy_copy.get("x_mitre_analytic_refs") or []:
                    if isinstance(ref, str) and ref in analytics_by_id:
                        analytics.append(analytics_by_id[ref])
                strategy_copy["x_attackcti_analytics"] = analytics
                strategy_objs.append(strategy_copy)
            if strategy_objs:
                context[tid] = strategy_objs
        return context

    def enrich_techniques_with_data_components(self, techniques: list[Any]) -> list[Any]:
        """Attach full data component objects under each enriched log-source entry.

        This method expects techniques to already have the detection enrichment graph
        (`x_attackcti_detection_strategies -> x_attackcti_analytics -> x_attackcti_log_sources`).

        Each log-source dict receives an additional `x_attackcti_data_component` field
        containing the resolved `x-mitre-data-component` object (as a dictionary) when
        available. To keep payloads small, only a compact subset of fields is retained
        (`id`, `type`, `spec_version`, `name`, `description`, `external_references`).
        """
        component_ids: set[str] = set()
        for technique in techniques:
            if not isinstance(technique, dict):
                technique = as_dict(technique)
            for strategy in technique.get("x_attackcti_detection_strategies") or []:
                if not isinstance(strategy, dict):
                    continue
                for analytic in strategy.get("x_attackcti_analytics") or []:
                    if not isinstance(analytic, dict):
                        continue
                    for log_source in analytic.get("x_attackcti_log_sources") or []:
                        if not isinstance(log_source, dict):
                            continue
                        ref = log_source.get("x_mitre_data_component_ref")
                        if isinstance(ref, str) and ref:
                            component_ids.add(ref)

        if not component_ids:
            return techniques

        logger.debug("Resolving %d data component ids for enrichment", len(component_ids))
        if callable(self._get_data_components_by_ids_fn):
            components = self._get_data_components_by_ids_fn(component_ids, stix_format=True)
        else:
            components = query_stix_objects_by_ids(
                data_source=self._data_source,
                stix_type="x-mitre-data-component",
                ids=component_ids,
            )
        components_by_id: dict[str, dict[str, Any]] = {}
        kept_fields = {
            "id",
            "type",
            "spec_version",
            "name",
            "description",
            "external_references",
        }
        for component in components or []:
            component_dict = as_dict(component)
            cid = component_dict.get("id")
            if isinstance(cid, str) and cid:
                # Drop heavy fields (e.g., x_mitre_log_sources) to keep enrichment lightweight.
                components_by_id[cid] = {k: v for k, v in component_dict.items() if k in kept_fields}

        enriched: list[Any] = []
        for technique in techniques:
            technique_dict = as_dict(technique)
            strategies = technique_dict.get("x_attackcti_detection_strategies") or []
            if not isinstance(strategies, list) or not strategies:
                enriched.append(technique)
                continue

            new_strategies: list[dict[str, Any]] = []
            for strategy in strategies:
                if not isinstance(strategy, dict):
                    continue
                strategy_copy = dict(strategy)
                analytics = strategy_copy.get("x_attackcti_analytics") or []
                new_analytics: list[dict[str, Any]] = []
                for analytic in analytics:
                    if not isinstance(analytic, dict):
                        continue
                    analytic_copy = dict(analytic)
                    log_sources = analytic_copy.get("x_attackcti_log_sources") or []
                    new_log_sources: list[dict[str, Any]] = []
                    for log_source in log_sources:
                        if not isinstance(log_source, dict):
                            continue
                        log_source_copy = dict(log_source)
                        ref = log_source_copy.get("x_mitre_data_component_ref")
                        if isinstance(ref, str) and ref in components_by_id:
                            log_source_copy["x_attackcti_data_component"] = dict(components_by_id[ref])
                        new_log_sources.append(log_source_copy)
                    analytic_copy["x_attackcti_log_sources"] = new_log_sources
                    new_analytics.append(analytic_copy)
                strategy_copy["x_attackcti_analytics"] = new_analytics
                new_strategies.append(strategy_copy)

            if isinstance(technique, dict):
                updated = dict(technique)
                updated["x_attackcti_detection_strategies"] = new_strategies
                enriched.append(updated)
            else:
                try:
                    from stix2.versioning import new_version as stix_new_version

                    enriched.append(stix_new_version(technique, x_attackcti_detection_strategies=new_strategies))
                except Exception:
                    enriched.append(technique)

        logger.debug("Enriched %d techniques with data components", len(enriched))
        return enriched

    def get_detection_strategies(self, *, stix_format: bool = True) -> list[dict[str, Any]]:
        """Return all detection strategies.

        Parameters
        ----------
        stix_format
            If `True`, returns dict-like STIX objects; if `False`, parses to
            the `x-mitre-detection-strategy` Pydantic model (dicts).

        Returns
        -------
        list[dict[str, Any]]
            Detection strategy objects.
        """
        strategies = self._data_source.query(Filter("type", "=", "x-mitre-detection-strategy"))
        if not stix_format:
            return self._parse_fn(strategies, DetectionStrategyModel)
        return [as_dict(s) for s in strategies]

    def get_detection_strategies_by_technique(self, technique: str | dict[str, Any], *, stix_format: bool = True) -> list[dict[str, Any]]:
        """Return detection strategies that `detect` a technique.

        Parameters
        ----------
        technique
            Technique STIX id string or a technique dict with an `id` field.
        stix_format
            If `True`, returns dict-like STIX objects; if `False`, parses to
            the `x-mitre-detection-strategy` Pydantic model (dicts).

        Returns
        -------
        list[dict[str, Any]]
            Detection strategies linked to the technique.

        Raises
        ------
        ValueError
            If `technique` does not contain a valid technique id.
        """
        technique_id = technique if isinstance(technique, str) else technique.get("id")
        if not isinstance(technique_id, str) or not technique_id:
            raise ValueError("technique must be a STIX id string or a technique dict with an 'id' field")

        detects = self._detects_relationships()
        strategy_ids = {
            r.get("source_ref")
            for r in detects
            if r.get("target_ref") == technique_id and get_type_from_id(r.get("source_ref")) == "x-mitre-detection-strategy"
        }
        strategy_ids = {sid for sid in strategy_ids if isinstance(sid, str) and sid}
        if not strategy_ids:
            return []

        strategies = self._data_source.query(Filter("type", "=", "x-mitre-detection-strategy"))
        selected = [s for s in strategies if as_dict(s).get("id") in strategy_ids]
        if not stix_format:
            return self._parse_fn(selected, DetectionStrategyModel)
        return [as_dict(s) for s in selected]

    def get_analytics_by_technique(self, technique: str | dict[str, Any], *, stix_format: bool = True) -> list[dict[str, Any]]:
        """Return analytics linked to a technique via detection strategies.

        Parameters
        ----------
        technique
            Technique STIX id string or technique dict with an `id` field.
        stix_format
            If `True`, return STIX-like dict objects; if `False`, parse to
            the `x-mitre-analytic` Pydantic model.

        Returns
        -------
        list[dict[str, Any]]
            Analytics associated with detection strategies for the technique.
        """
        strategies = self.get_detection_strategies_by_technique(technique, stix_format=True)
        analytic_ids: set[str] = set()
        for strategy in strategies:
            for ref in strategy.get("x_mitre_analytic_refs") or []:
                if isinstance(ref, str) and ref:
                    analytic_ids.add(ref)
        if not analytic_ids:
            return []

        analytics_map = self._get_analytics_by_ids_fn(analytic_ids)
        analytics = list(analytics_map.values())
        if not stix_format:
            return self._parse_fn(analytics, AnalyticModel)
        return analytics

    def get_log_source_references_by_technique(self, technique: str | dict[str, Any]) -> list[dict[str, Any]]:
        """Return unique log source references linked to a technique via analytics.

        Parameters
        ----------
        technique
            Technique STIX id string or technique dict with an `id` field.

        Returns
        -------
        list[dict[str, Any]]
            Unique log source reference objects with `x_mitre_data_component_ref`,
            `name`, and `channel` keys.
        """
        analytics = self.get_analytics_by_technique(technique, stix_format=True)
        refs: list[dict[str, Any]] = []
        for analytic in analytics:
            for ref in analytic.get("x_mitre_log_source_references") or []:
                if isinstance(ref, dict):
                    refs.append(ref)

        seen: set[tuple[str, str, str]] = set()
        out: list[dict[str, Any]] = []
        for ref in refs:
            dc_ref = ref.get("x_mitre_data_component_ref")
            name = ref.get("name")
            channel = ref.get("channel")
            if not (isinstance(dc_ref, str) and isinstance(name, str) and isinstance(channel, str)):
                continue
            key = (dc_ref, name, channel)
            if key in seen:
                continue
            seen.add(key)
            out.append({"x_mitre_data_component_ref": dc_ref, "name": name, "channel": channel})
        return out

    def get_data_components_by_technique_via_analytics(
        self,
        technique: str | dict[str, Any],
        *,
        stix_format: bool = True,
        data_components: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Return data components linked to a technique via log source references.

        Parameters
        ----------
        technique
            Technique STIX id string or technique dict with an `id` field.
        stix_format
            If `True`, return STIX-like dict objects; if `False`, parse to
            the `x-mitre-data-component` Pydantic model.
        data_components
            Optional pre-fetched data component objects to reuse.

        Returns
        -------
        list[dict[str, Any]]
            Data component objects associated with the technique.
        """
        refs = self.get_log_source_references_by_technique(technique)
        dc_ids = {r["x_mitre_data_component_ref"] for r in refs if isinstance(r.get("x_mitre_data_component_ref"), str)}
        if not dc_ids:
            return []

        return self._get_data_components_by_ids_fn(
            dc_ids,
            stix_format=stix_format,
            data_components=data_components,
        )

    def enrich_techniques_with_detections(self, techniques: list[Any]) -> list[Any]:
        """Enrich techniques with detection strategies, analytics, and log source references.

        This enrichment follows the newer ATT&CK detection model:
        `x-mitre-detection-strategy --detects--> attack-pattern` and
        `x-mitre-detection-strategy.x_mitre_analytic_refs -> x-mitre-analytic`,
        where analytics include `x_mitre_log_source_references`.

        The enrichment is attached under the custom property
        `x_attackcti_detection_strategies` to avoid using deprecated ATT&CK fields.
        """
        technique_ids = [tid for technique in techniques if (tid := stix_id(technique)) is not None]
        logger.debug("Enriching %d techniques with detection context", len(technique_ids))
        if not technique_ids:
            return techniques

        detection_context = self.get_detection_context_for_techniques(technique_ids)
        if not detection_context:
            return techniques

        enriched: list[Any] = []
        for technique in techniques:
            tid = stix_id(technique)
            strategy_objs = detection_context.get(tid)
            if not isinstance(tid, str) or not strategy_objs:
                enriched.append(technique)
                continue

            # Each technique receives its own copies of the strategy dicts.
            strategy_objs = [dict(strategy) for strategy in strategy_objs]

            if isinstance(technique, dict):
                updated = dict(technique)
                updated["x_attackcti_detection_strategies"] = strategy_objs
                enriched.append(updated)
            else:
                try:
                    from stix2.versioning import new_version as stix_new_version

                    enriched.append(stix_new_version(technique, x_attackcti_detection_strategies=strategy_objs))
                except Exception:
                    enriched.append(technique)
        logger.debug("Enriched %d techniques with detection strategies", len(enriched))
        return enriched
