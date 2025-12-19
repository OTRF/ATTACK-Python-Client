"""Cross-domain technique query helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Union

from stix2 import CompositeDataSource, Filter
from stix2.v21.sdo import AttackPattern as AttackPatternV21

from ...models import Technique as TechniqueModel
from ...utils.stix import parse_stix_objects, remove_revoked_deprecated


class TechniquesClient:
    """Query techniques from a composite STIX data source."""

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        remove_fn: Callable = remove_revoked_deprecated,
        parse_fn: Callable = parse_stix_objects,
        enrich_with_detections_fn: Callable | None = None,
        enrich_data_components_fn: Callable | None = None,
    ) -> None:
        """Initialize the client with a data source and helper callbacks.

        Parameters
        ----------
        data_source : CompositeDataSource
            Composite STIX2 data source.
        remove_fn : Callable
            Callable used to remove revoked/deprecated objects.
        parse_fn : Callable
            Callable used to parse STIX objects into Pydantic-backed dicts.
        enrich_with_detections_fn : Callable, optional
            Callable used to enrich techniques with detection-strategy/analytic context.
        enrich_data_components_fn : Callable, optional
            Callable used to enrich techniques with data component context.
        """
        self._data_source = data_source
        self._remove_fn = remove_fn
        self._parse_fn = parse_fn
        self._enrich_with_detections_fn = enrich_with_detections_fn
        self._enrich_data_components_fn = enrich_data_components_fn

    def set_enrich_with_detections_fn(self, enrich_fn: Callable | None) -> None:
        """Set the default detection enrichment callback for techniques.

        Parameters
        ----------
        enrich_fn : Callable | None
            Callable that accepts a list of techniques and returns an enriched list.
            Set to `None` to disable enrichment.
        """
        self._enrich_with_detections_fn = enrich_fn
    
    def set_enrich_data_components_fn(self, enrich_fn: Callable | None) -> None:
        """Set the default data component enrichment callback for techniques.

        Parameters
        ----------
        enrich_fn : Callable | None
            Callable that accepts a list of techniques and returns an enriched list.
            Set to `None` to disable enrichment.
        """
        self._enrich_data_components_fn = enrich_fn 
        
    def get_techniques(
        self,
        *,
        skip_revoked_deprecated: bool = True,
        include_subtechniques: bool = True,
        enrich_detections: bool = False,
        enrich_data_components: bool = False,
        stix_format: bool = True,
    ) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques across domains.

        Parameters
        ----------
        skip_revoked_deprecated : bool, optional
            When `True`, omit revoked/deprecated techniques.
        include_subtechniques : bool, optional
            When `True`, include sub-techniques.
        enrich_detections : bool, optional
            When `True`, enrich techniques with detection-strategy and analytic context
            (applied only if an enrichment callback is configured).
        enrich_data_components : bool, optional
            When `True`, enrich techniques with data component context (applied only if
            an enrichment callback is configured).
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries
            parsed to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Technique objects in the requested format.
        """
        if include_subtechniques:
            all_techniques = self._data_source.query([Filter("type", "=", "attack-pattern")])
        else:
            all_techniques = self._data_source.query([Filter("type", "=", "attack-pattern"), Filter("x_mitre_is_subtechnique", "=", False)])

        if skip_revoked_deprecated:
            all_techniques = self._remove_fn(all_techniques)
        if enrich_data_components:
            enrich_detections = True
        if enrich_detections and self._enrich_with_detections_fn is not None:
            all_techniques = self._enrich_with_detections_fn(all_techniques)
        if enrich_data_components and self._enrich_data_components_fn is not None:
            all_techniques = self._enrich_data_components_fn(all_techniques)
        if not stix_format:
            all_techniques = self._parse_fn(all_techniques, TechniqueModel)
        return all_techniques

    def get_technique_by_name(
        self,
        name: str,
        *,
        case: bool = True,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques matching a given name.

        Parameters
        ----------
        name : str
            Technique name to match.
        case : bool, optional
            When `True`, perform an exact case-sensitive match; when `False`, perform a
            case-insensitive containment match.
        skip_revoked_deprecated : bool, optional
            When `True`, omit revoked/deprecated techniques.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries
            parsed to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Matching technique objects in the requested format.
        """
        if not case:
            filter_objects = [Filter("type", "=", "attack-pattern"), Filter("name", "contains", name)]
            matched = self._data_source.query(filter_objects)
        else:
            filter_objects = [Filter("type", "=", "attack-pattern"), Filter("name", "=", name)]
            matched = self._data_source.query(filter_objects)

        if skip_revoked_deprecated:
            matched = self._remove_fn(matched)
        
        if not stix_format:
            matched = self._parse_fn(matched, TechniqueModel)
        return matched

    def get_techniques_by_data_components(
        self,
        *data_components: str,
        stix_format: bool = True,
    ) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques that reference specific data components via log sources.

        This uses the modern detection enrichment path:
        `Technique -> Detection strategy -> Analytic -> Log source references -> Data component ref`.
        It performs a case-insensitive containment match on data component names attached under
        `x_attackcti_data_component` (enabled by `enrich_data_components=True`).

        Parameters
        ----------
        data_components : str
            One or more substrings to match against data component names.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries parsed
            to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Techniques whose detection graph contains matching data component names.
        """
        if not data_components:
            return []

        # Ensure the detection graph and data components are attached.
        techniques = self.get_techniques(enrich_detections=True, enrich_data_components=True, stix_format=True)
        terms = [dc.lower() for dc in data_components if isinstance(dc, str) and dc]
        if not terms:
            return []  # pragma: no cover

        results: list[Any] = []
        for technique in techniques:
            t_dict = technique if isinstance(technique, dict) else technique._inner  # type: ignore[attr-defined]
            strategies = t_dict.get("x_attackcti_detection_strategies") or []
            matched = False
            for strategy in strategies:
                for analytic in strategy.get("x_attackcti_analytics") or []:
                    for log_source in analytic.get("x_attackcti_log_sources") or []:
                        comp = log_source.get("x_attackcti_data_component")
                        name = comp.get("name") if isinstance(comp, dict) else None
                        if isinstance(name, str) and any(term in name.lower() for term in terms):
                            matched = True
                            break
                    if matched:
                        break
                if matched:
                    break
            if matched:
                results.append(technique)

        if not stix_format:
            results = self._parse_fn(results, TechniqueModel)
        return results


    def get_techniques_by_content(self, *, content: str, stix_format: bool = True) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques whose descriptions contain the provided content.

        Parameters
        ----------
        content : str
            Substring to search for in technique descriptions.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries
            parsed to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Matching technique objects in the requested format.
        """
        all_techniques = self.get_techniques(stix_format=True)
        matched: list[Any] = []
        for tech in all_techniques:
            description = tech.get("description", "").lower()
            if content.lower() in description:
                matched.append(tech)
        if not stix_format:
            matched = self._parse_fn(matched, TechniqueModel)
        return matched


    def get_techniques_by_platform(self, *, name: str, case: bool = True, stix_format: bool = True) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques targeting a given platform.

        Parameters
        ----------
        name : str
            Platform name to match.
        case : bool, optional
            When `True`, use a STIX filter containment match; when `False`, perform a
            case-insensitive containment match in Python.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries
            parsed to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Matching technique objects in the requested format.
        """
        if not case:
            all_techniques = self.get_techniques(stix_format=True)
            matched = []
            for tech in all_techniques:
                if "x_mitre_platforms" in tech.keys():
                    for platform in tech["x_mitre_platforms"]:
                        if name.lower() in platform.lower():
                            matched.append(tech)
        else:
            filter_objects = [Filter("type", "=", "attack-pattern"), Filter("x_mitre_platforms", "contains", name)]
            matched = self._data_source.query(filter_objects)
        if not stix_format:
            matched = self._parse_fn(matched, TechniqueModel)
        return matched


    def get_techniques_by_tactic(self, *, name: str, case: bool = True, stix_format: bool = True) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques mapped to a given tactic (kill chain phase).

        Parameters
        ----------
        name : str
            Tactic/phase name to match.
        case : bool, optional
            When `True`, use a STIX filter exact match; when `False`, perform a
            case-insensitive match in Python.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries
            parsed to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Matching technique objects in the requested format.
        """
        if not case:
            all_techniques = self.get_techniques(stix_format=True)
            matched = []
            for tech in all_techniques:
                if "kill_chain_phases" in tech.keys():
                    if name.lower() in tech["kill_chain_phases"][0]["phase_name"].lower():
                        matched.append(tech)
        else:
            filter_objects = [Filter("type", "=", "attack-pattern"), Filter("kill_chain_phases.phase_name", "=", name)]
            matched = self._data_source.query(filter_objects)
        if not stix_format:
            matched = self._parse_fn(matched, TechniqueModel)
        return matched


    def get_techniques_since_time(self, *, timestamp: str, stix_format: bool = True) -> List[Union[AttackPatternV21, Dict[str, Any]]]:
        """Return techniques created after the provided timestamp.

        Parameters
        ----------
        timestamp : str
            Timestamp string to filter by (STIX `created` field).
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, return dictionaries
            parsed to the `Technique` Pydantic model.

        Returns
        -------
        list[AttackPatternV21 | dict[str, Any]]
            Matching technique objects in the requested format.
        """
        filter_objects = [Filter("type", "=", "attack-pattern"), Filter("created", ">", timestamp)]
        matched = self._data_source.query(filter_objects)
        if not stix_format:
            matched = self._parse_fn(matched, TechniqueModel)
        return matched
