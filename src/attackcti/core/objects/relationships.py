"""Relationship helpers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

from stix2 import CompositeDataSource, Filter
from stix2.utils import get_type_from_id
from stix2.v21.sdo import AttackPattern as AttackPattern_v21
from stix2.v21.sdo import Malware as Malware_v21
from stix2.v21.sdo import Tool as Tool_v21
from stix2.v21.sro import Relationship as Relationship_v21

from ...models import DataComponent as DataComponentModel
from ...models import DataSource as DataSourceModel
from ...models import GroupTechnique as GroupTechniqueModel
from ...models import Relationship as RelationshipModel
from ...models import Software as SoftwareModel
from ...models import Technique as TechniqueModel
from ...utils.stix import (
    as_dict,
    parse_stix_objects,
    relationship_source_ref,
    relationship_target_ref,
    remove_revoked_deprecated,
    stix_id,
    stix_type,
)


class RelationshipsClient:
    """DataSources query helper class."""

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        get_groups_fn: Callable[..., Any] | None = None,
        get_techniques_fn: Callable[..., Any] | None = None,
        get_data_components_fn: Callable[..., Any] | None = None,
        get_data_sources_fn: Callable[..., Any] | None = None,
        remove_fn: Callable[[List], List] = remove_revoked_deprecated,
        parse_fn: Callable[..., List[Dict[str, Any]]] = parse_stix_objects,
    ) -> None:
        """Initialize RelationshipsClient.

        Args:
            data_source: The data source to query.
        """
        self.data_source = data_source
        self._get_techniques_fn = get_techniques_fn
        self._get_groups_fn = get_groups_fn
        self._get_data_components_fn = get_data_components_fn
        self._get_data_sources_fn = get_data_sources_fn
        self._remove_fn = remove_fn
        self._parse_fn = parse_fn

    def set_get_techniques_fn(self, fn: Callable[..., Any] | None) -> None:
        """Set or update the injected get_techniques callback."""
        self._get_techniques_fn = fn

    def set_get_groups_fn(self, fn: Callable[..., Any] | None) -> None:
        """Set or update the injected get_groups callback."""
        self._get_groups_fn = fn

    def set_get_data_components_fn(self, fn: Callable[..., Any] | None) -> None:
        """Set or update the injected get_data_components callback."""
        self._get_data_components_fn = fn

    def set_get_data_sources_fn(self, fn: Callable[..., Any] | None) -> None:
        """Set or update the injected get_data_sources callback."""
        self._get_data_sources_fn = fn

    def _groups(self, *, stix_format: bool = True) -> list[Any]:
        if self._get_groups_fn is not None:
            return self._get_groups_fn(stix_format=stix_format)
        groups = self.data_source.query([Filter("type", "=", "intrusion-set")])
        return groups if stix_format else self._parse_fn(groups, DataComponentModel)  # type: ignore[arg-type]

    def _techniques(self, *, stix_format: bool = True) -> list[Any]:
        if self._get_techniques_fn is not None:
            return self._get_techniques_fn(stix_format=stix_format)
        techniques = self.data_source.query([Filter("type", "=", "attack-pattern")])
        return techniques if stix_format else self._parse_fn(techniques, TechniqueModel)

    def _data_components(self, *, stix_format: bool = True) -> list[Any]:
        if self._get_data_components_fn is not None:
            return self._get_data_components_fn(stix_format=stix_format)
        comps = self.data_source.query([Filter("type", "=", "x-mitre-data-component")])
        return comps if stix_format else self._parse_fn(comps, DataComponentModel)

    def _data_sources(self, *, stix_format: bool = True) -> list[Any]:
        if self._get_data_sources_fn is not None:
            return self._get_data_sources_fn(stix_format=stix_format)
        ds = self.data_source.query([Filter("type", "=", "x-mitre-data-source")])
        return ds if stix_format else self._parse_fn(ds, DataSourceModel)


    def get_relationships(
        self,
        *,
        relationship_type: str | None = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """Return relationship objects from the composite data source.

        Parameters
        ----------
        relationship_type
            Optional relationship type filter (e.g., ``uses``, ``mitigates``, ``subtechnique-of``,
            ``detects``, ``revoked-by``). If `None`, returns all relationship types.
        skip_revoked_deprecated
            If `True`, remove revoked and deprecated relationships.
        stix_format
            If `True`, return python-stix2 relationship objects; if `False`, parse into the
            project `Relationship` Pydantic model (dicts).

        Returns
        -------
        list[Relationship_v21 | dict[str, Any]]
            Relationship objects (raw STIX or parsed dicts).

        Raises
        ------
        ValueError
            If `relationship_type` is not a supported value.
        """
        allowed_types = {"uses", "mitigates", "subtechnique-of", "detects", "revoked-by"}
        if relationship_type is not None and relationship_type not in allowed_types:
            raise ValueError(f"Valid relationship types must be one of {sorted(allowed_types)}")

        filters: list[Filter] = [Filter("type", "=", "relationship")]
        if relationship_type is not None:
            filters.append(Filter("relationship_type", "=", relationship_type))

        relationships = self.data_source.query(filters)
        if skip_revoked_deprecated:
            relationships = self._remove_fn(relationships)
        if not stix_format:
            relationships = self._parse_fn(relationships, RelationshipModel)
        return relationships
    
    def get_relationships_by_object(
        self,
        stix_object: Any,
        *,
        relationship_type: Optional[str] = None,
        source_only: bool = False,
        target_only: bool = False,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """Retrieve relationships associated with a STIX object.

        Parameters
        ----------
        stix_object
            STIX object or dict. Must include an `id` field/attribute.
        relationship_type
            Relationship type filter (e.g., ``uses``, ``mitigates``, ``detects``). If omitted,
            this method attempts to infer a reasonable default from the object's ``type``.
            If the type is unknown, all relationship types are returned.
        source_only
            If True, only returns relationships where `stix_object` is the source.
        target_only
            If True, only returns relationships where `stix_object` is the target.
        skip_revoked_deprecated
            If True, filters out revoked and deprecated relationship objects.
        stix_format
            If True, returns STIX Relationship objects. If False, parses to the `Relationship`
            Pydantic model.

        Returns
        -------
        list[Relationship_v21 | dict[str, Any]]
            Relationship objects (raw STIX or parsed dicts).

        Raises
        ------
        ValueError
            If both `source_only` and `target_only` are set, or if `stix_object` does not
            contain a usable STIX id.
        """
        if source_only and target_only:
            raise ValueError("You can only set source_only or target_only but not both")

        object_id = stix_id(stix_object)
        if object_id is None:
            raise ValueError("stix_object must be a STIX object or dict with a non-empty 'id'")

        # Let callers explicitly request "all relationship types" by passing relationship_type=None.
        # If the caller omitted it, try a best-effort inference for convenience.
        if relationship_type is None:
            obj_type = stix_type(stix_object)
            type_lookup = {
                "course-of-action": "mitigates",
                "x-mitre-data-component": "detects",
                "x-mitre-detection-strategy": "detects",
                "attack-pattern": "subtechnique-of",
                "malware": "uses",
                "tool": "uses",
                "intrusion-set": "uses",
            }
            relationship_type = type_lookup.get(obj_type)

        if source_only:
            relationships = self.data_source.relationships(stix_object, relationship_type, source_only=True)
        elif target_only:
            relationships = self.data_source.relationships(stix_object, relationship_type, target_only=True)
        else:
            relationships = self.data_source.relationships(stix_object, relationship_type)

        if skip_revoked_deprecated:
            relationships = self._remove_fn(relationships)

        if not stix_format:
            relationships = self._parse_fn(relationships, RelationshipModel)

        return relationships


    def get_techniques_by_relationship(
        self,
        stix_object: Any | None = None,
        *,
        relationship_type: str | None = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """Return technique objects linked via relationships.

        This helper is a convenience method that:
        1) selects relationships (optionally scoped to a STIX object), then
        2) resolves the technique (`attack-pattern`) objects referenced by those relationships.

        Parameters
        ----------
        stix_object
            Optional STIX object/dict used to scope the relationship search.
        relationship_type
            Optional relationship type (e.g., ``uses``, ``mitigates``, ``detects``, ``subtechnique-of``).
            If `None` and `stix_object` is provided, a best-effort default is inferred by
            `get_relationships_by_object`.
        skip_revoked_deprecated
            If `True`, exclude revoked/deprecated techniques.
        stix_format
            If `True`, return python-stix2 technique objects; if `False`, parse into the `Technique`
            Pydantic model (dicts).

        Returns
        -------
        list[AttackPattern_v21 | dict[str, Any]]
            Technique objects linked via the selected relationships.

        Raises
        ------
        ValueError
            If `relationship_type` is not supported when querying globally (no `stix_object`).
        """
        technique_ref_fn = relationship_target_ref
        if stix_object is not None:
            requested_type = relationship_type
            if requested_type is None:
                obj_type = stix_type(stix_object)
                if obj_type == "attack-pattern":
                    # Most callers want "subtechniques for this technique". STIX models `subtechnique-of`
                    # as subtechnique(source) -> parent(target), so if the input is a parent technique
                    # we must look at relationships where it is the target.
                    is_sub = (
                        stix_object.get("x_mitre_is_subtechnique")
                        if isinstance(stix_object, dict)
                        else getattr(stix_object, "x_mitre_is_subtechnique", None)
                    )
                    requested_type = "subtechnique-of"
                    relationships = self.get_relationships_by_object(
                        stix_object=stix_object,
                        relationship_type=requested_type,
                        skip_revoked_deprecated=skip_revoked_deprecated,
                        source_only=bool(is_sub),
                        target_only=not bool(is_sub),
                    )
                    technique_ref_fn = relationship_target_ref if bool(is_sub) else relationship_source_ref
                else:
                    relationships = self.get_relationships_by_object(
                        stix_object=stix_object,
                        relationship_type=None,
                        skip_revoked_deprecated=skip_revoked_deprecated,
                        source_only=True,
                    )
            else:
                relationships = self.get_relationships_by_object(
                    stix_object=stix_object,
                    relationship_type=requested_type,
                    skip_revoked_deprecated=skip_revoked_deprecated,
                    source_only=True,
                )
        else:
            if relationship_type is not None:
                allowed = {"uses", "mitigates", "subtechnique-of", "detects", "revoked-by"}
                if relationship_type not in allowed:
                    raise ValueError(f"Valid relationship types must be one of {sorted(allowed)}")
            relationships = self.get_relationships(
                relationship_type=relationship_type,
                skip_revoked_deprecated=skip_revoked_deprecated,
                stix_format=True,
            )

        technique_ids: set[str] = set()
        for rel in relationships:
            if relationship_type == "subtechnique-of" and stix_object is None:
                candidates = (relationship_source_ref(rel), relationship_target_ref(rel))
            else:
                candidates = (technique_ref_fn(rel),)
            for tid in candidates:
                if isinstance(tid, str) and get_type_from_id(tid) == "attack-pattern":
                    technique_ids.add(tid)
        if not technique_ids:
            return []

        all_objects = self.data_source.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("id", "in", list(technique_ids)),
            ]
        )

        if skip_revoked_deprecated:
            all_objects = self._remove_fn(all_objects)

        if not stix_format:
            all_objects = self._parse_fn(all_objects, TechniqueModel)

        return all_objects


    def get_techniques_used_by_group(
        self,
        stix_object: Any = None,
        *,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """Return techniques used by a group (intrusion-set).

        This is a convenience wrapper around `get_techniques_by_relationship` that defaults
        to the common "group uses techniques" traversal.

        Parameters
        ----------
        stix_object
            Group STIX object or dict (typically type ``intrusion-set``).
        skip_revoked_deprecated
            If `True`, exclude revoked/deprecated techniques.
        stix_format
            If `True`, return python-stix2 technique objects; if `False`, parse into the
            `Technique` Pydantic model (dicts).

        Returns
        -------
        list[AttackPattern_v21 | dict[str, Any]]
            Technique objects used by the group.
        """
        return self.get_techniques_by_relationship(
            stix_object=stix_object,
            relationship_type=None,
            skip_revoked_deprecated=skip_revoked_deprecated,
            stix_format=stix_format,
        )


    def get_techniques_used_by_software(
        self,
        stix_object: Any = None,
        *,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """Return techniques used by a software object (malware/tool).

        This is a convenience wrapper around `get_techniques_by_relationship` that defaults
        to the common "software uses techniques" traversal.

        Parameters
        ----------
        stix_object
            Software STIX object or dict (typically type ``malware`` or ``tool``).
        skip_revoked_deprecated
            If `True`, exclude revoked/deprecated techniques.
        stix_format
            If `True`, return python-stix2 technique objects; if `False`, parse into the
            `Technique` Pydantic model (dicts).

        Returns
        -------
        list[AttackPattern_v21 | dict[str, Any]]
            Technique objects used by the software.
        """
        return self.get_techniques_by_relationship(
            stix_object=stix_object,
            relationship_type=None,
            skip_revoked_deprecated=skip_revoked_deprecated,
            stix_format=stix_format,
        )
    
    def get_software_used_by_group(
        self,
        stix_object: Any = None,
        *,
        stix_format: bool = True,
        batch_size: int = 10,
    ) -> List[Union[Malware_v21, Tool_v21, Dict[str, Any]]]:
        """Return software (malware/tools) used by a group (intrusion-set).

        Parameters
        ----------
        stix_object
            Group STIX object or dict (typically type ``intrusion-set``).
        stix_format
            If `True`, return python-stix2 objects; if `False`, parse into the `Software`
            Pydantic model (dicts).
        batch_size
            Batch size used when querying by ID lists (use smaller values if a remote backend
            returns URI-too-long errors).

        Returns
        -------
        list[Malware_v21 | Tool_v21 | dict[str, Any]]
            Malware/tool objects used by the group.
        """
        relationships = self.get_relationships_by_object(stix_object=stix_object, relationship_type="uses", source_only=True)

        software_ids: list[str] = []
        for rel in relationships:
            target = relationship_target_ref(rel)
            if isinstance(target, str) and get_type_from_id(target) in {"malware", "tool"}:
                software_ids.append(target)
        if not software_ids:
            return []

        # Deduplicate while preserving a stable order.
        seen: set[str] = set()
        unique_ids: list[str] = []
        for sid in software_ids:
            if sid not in seen:
                seen.add(sid)
                unique_ids.append(sid)

        all_software: list[Any] = []
        for i in range(0, len(unique_ids), batch_size):
            batch_ids = unique_ids[i : i + batch_size]
            all_software.extend(
                self.data_source.query(
                    [
                        Filter("type", "in", ["malware", "tool"]),
                        Filter("id", "in", batch_ids),
                    ]
                )
            )

        if not stix_format:
            all_software = self._parse_fn(all_software, SoftwareModel)
        return all_software


    def get_techniques_used_by_group_software(
        self,
        stix_object: Any = None,
        *,
        stix_format: bool = True,
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """Return techniques used by software used by a group.

        This is a two-hop traversal:
        1) group `uses` → software (malware/tool)
        2) software `uses` → techniques

        Parameters
        ----------
        stix_object
            Group STIX object or dict (typically type ``intrusion-set``).
        stix_format
            If `True`, return python-stix2 technique objects; if `False`, parse into the
            `Technique` Pydantic model (dicts).

        Returns
        -------
        list[AttackPattern_v21 | dict[str, Any]]
            Technique objects used by software used by the group.
        """
        relationships = self.get_relationships_by_object(stix_object=stix_object, relationship_type="uses", source_only=True)

        software_ids: list[str] = []
        for rel in relationships:
            target = relationship_target_ref(rel)
            if isinstance(target, str) and get_type_from_id(target) in {"malware", "tool"}:
                software_ids.append(target)
        if not software_ids:
            return []

        software_uses = self.data_source.query(
            [
                Filter("type", "=", "relationship"),
                Filter("relationship_type", "=", "uses"),
                Filter("source_ref", "in", list(set(software_ids))),
            ]
        )

        technique_ids: set[str] = set()
        for rel in software_uses:
            target = relationship_target_ref(rel)
            if isinstance(target, str) and get_type_from_id(target) == "attack-pattern":
                technique_ids.add(target)
        if not technique_ids:
            return []

        matched_techniques = self.data_source.query(
            [
                Filter("type", "=", "attack-pattern"),
                Filter("id", "in", list(technique_ids)),
            ]
        )
        if not stix_format:
            matched_techniques = self._parse_fn(matched_techniques, TechniqueModel)
        return matched_techniques


    def get_techniques_mitigated_by_mitigations(
        self,
        stix_object: Any = None,
        *,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """Return techniques mitigated by a mitigation (or all mitigations).

        Parameters
        ----------
        stix_object
            Optional mitigation STIX object or dict (typically type ``course-of-action``).
            If omitted, returns techniques mitigated by any mitigation across the dataset.
        skip_revoked_deprecated
            If `True`, exclude revoked/deprecated techniques.
        stix_format
            If `True`, return python-stix2 technique objects; if `False`, parse into the
            `Technique` Pydantic model (dicts).

        Returns
        -------
        list[AttackPattern_v21 | dict[str, Any]]
            Technique objects mitigated by the selected mitigation(s).
        """
        return self.get_techniques_by_relationship(
            stix_object=stix_object,
            relationship_type="mitigates",
            skip_revoked_deprecated=skip_revoked_deprecated,
            stix_format=stix_format,
        )

    def get_techniques_used_by_all_groups(self, *, stix_format: bool = True) -> List[Any]:
        """Return group-technique usage details across all groups.

        This is a convenience function that joins:
        - groups (`intrusion-set`)
        - `uses` relationships from groups → techniques
        - technique metadata (tactics/platforms/data-sources, etc.)

        Args:
            stix_format: If True, returns plain dicts. If False, parses to the `GroupTechnique` Pydantic model.

        Returns
        -------
            A list of group-technique usage records.
        """
        groups = self._groups(stix_format=True)
        techniques = self._techniques(stix_format=True)

        rel_filters = [
            Filter("type", "=", "relationship"),
            Filter("relationship_type", "=", "uses"),
        ]
        relationships = self.data_source.query(rel_filters)

        group_uses: list[Any] = []
        for rel in relationships:
            source_ref = getattr(rel, "source_ref", None)
            target_ref = getattr(rel, "target_ref", None)
            if not isinstance(source_ref, str) or not isinstance(target_ref, str):
                continue
            if get_type_from_id(source_ref) != "intrusion-set":
                continue
            if get_type_from_id(target_ref) != "attack-pattern":
                continue
            group_uses.append(rel)

        group_by_id: dict[str, Any] = {}
        for group in groups:
            group_id = stix_id(group)
            if group_id is not None:
                group_by_id[group_id] = group

        technique_by_id: dict[str, Any] = {}
        for technique in techniques:
            technique_id = stix_id(technique)
            if technique_id is not None:
                technique_by_id[technique_id] = technique

        out: list[dict[str, Any]] = []
        for rel in group_uses:
            group = group_by_id.get(rel.source_ref)
            technique = technique_by_id.get(rel.target_ref)
            if group is None or technique is None:
                continue

            group_dict = as_dict(group)

            group_dict["technique_ref"] = rel.target_ref
            group_dict["relationship_description"] = getattr(rel, "description", None)
            group_dict["relationship_id"] = getattr(rel, "id", None)

            technique_dict = as_dict(technique)

            revoked_val = technique_dict.get("revoked")
            group_dict["revoked"] = bool(revoked_val) if isinstance(revoked_val, bool) else False
            group_dict["technique"] = technique_dict.get("name")
            group_dict["technique_description"] = technique_dict.get("description")
            group_dict["tactic"] = technique_dict.get("kill_chain_phases", []) or []

            # Prefer the MITRE ATT&CK external id; fallback to any external_id if present.
            group_dict["technique_id"] = None
            external_refs = technique_dict.get("external_references") or []
            if isinstance(external_refs, list):
                for ref in external_refs:
                    if isinstance(ref, dict):
                        source = ref.get("source_name")
                        external_id = ref.get("external_id")
                    else:
                        source = getattr(ref, "source_name", None)
                        external_id = getattr(ref, "external_id", None)
                    if group_dict["technique_id"] is None and external_id:
                        group_dict["technique_id"] = external_id
                    if source == "mitre-attack" and external_id:
                        group_dict["technique_id"] = external_id
                        break

            group_dict["technique_matrix"] = technique_dict.get("x_mitre_domains")
            group_dict["platform"] = technique_dict.get("x_mitre_platforms")

            out.append(group_dict)

        if not stix_format:
            return self._parse_fn(out, GroupTechniqueModel)
        return out


    def export_groups_navigator_layers(self, *, output_dir: str | Path = ".") -> None:
        """Export group technique usage in MITRE Navigator Layers format.

        Writes one JSON layer file per group into `output_dir`.

        Args:
            output_dir: Directory where layer files will be written.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        techniques_used = self.get_techniques_used_by_all_groups(stix_format=True)
        groups = self._groups(stix_format=True)

        groups_list: list[dict[str, list[dict[str, Any]]]] = []
        for group in groups:
            group_dict = group if isinstance(group, dict) else as_dict(group)
            name = group_dict.get("name")
            if isinstance(name, str):
                groups_list.append({name: []})

        for group in groups_list:
            for group_name, techniques_list in group.items():
                for usage in techniques_used:
                    if usage.get("name") != group_name:
                        continue
                    technique_dict: dict[str, Any] = {
                        "techniqueId": usage.get("technique_id"),
                        "techniqueName": usage.get("technique"),
                        "comment": usage.get("relationship_description"),
                        "tactic": usage.get("tactic"),
                        "group_id": None,
                    }
                    external_refs = usage.get("external_references") or []
                    if external_refs and isinstance(external_refs, list) and isinstance(external_refs[0], dict):
                        technique_dict["group_id"] = external_refs[0].get("external_id")
                    techniques_list.append(technique_dict)

        for group in groups_list:
            for name, techniques in group.items():
                if not techniques:
                    continue
                group_id = techniques[0].get("group_id") or "unknown"
                actor_layer = {
                    "description": f"Enterprise techniques used by {name}, ATT&CK group {group_id} v1.0",
                    "name": f"{name} ({group_id})",
                    "domain": "enterprise-attack",
                    "versions": {
                        "attack": "18",
                        "navigator": "5.2.0",
                        "layer": "4.5"
                    },
                    "techniques": [
                        {
                            "score": 1,
                            "techniqueID": t.get("techniqueId"),
                            "techniqueName": t.get("techniqueName"),
                            "comment": t.get("comment"),
                        }
                        for t in techniques
                    ],
                    "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0, "maxValue": 1},
                    "legendItems": [{"label": f"used by {name}", "color": "#ff6666"}],
                }
                (output_path / f"{name}_{group_id}.json").write_text(json.dumps(actor_layer), encoding="utf-8")
