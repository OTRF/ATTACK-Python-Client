"""Convenience wrapper for cross-domain query helpers."""

from __future__ import annotations

from typing import Any

from stix2 import CompositeDataSource, Filter

from ..models import pydantic_model_mapping
from ..utils.stix import parse_stix_objects, remove_revoked_deprecated
from .objects.analytics import AnalyticsClient
from .objects.campaigns import CampaignsClient
from .objects.data_sources import DataSourcesClient
from .objects.detections import DetectionsClient
from .objects.groups import GroupsClient
from .objects.mitigations import MitigationsClient
from .objects.relationships import RelationshipsClient
from .objects.software import SoftwareClient
from .objects.tactics import TacticsClient
from .objects.techniques import TechniquesClient


class QueryClient:
    """Cross-domain query client (COMPOSITE_DS-backed)."""

    def __init__(
        self,
        data_source: CompositeDataSource,
        *,
        pydantic_map: dict[str, object] | None = None,
    ) -> None:
        """Initialize the query client with shared data source and helpers."""
        self.data_source = data_source
        self.pydantic_map = pydantic_map or pydantic_model_mapping

        # Initialize object-specific clients
        self._relationships_client: RelationshipsClient = RelationshipsClient(
            data_source=data_source,
            get_techniques_fn=None,
            get_groups_fn=None,
            get_data_components_fn=None,
            get_data_sources_fn=None,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._techniques_client = TechniquesClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._campaigns_client: CampaignsClient = CampaignsClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._mitigations_client: MitigationsClient = MitigationsClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._analytics_client: AnalyticsClient = AnalyticsClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._detections_client: DetectionsClient = DetectionsClient(
            data_source=data_source,
            get_analytics_by_ids_fn = None,
            get_data_components_by_ids_fn = None,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._groups_client: GroupsClient = GroupsClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._data_sources_client: DataSourcesClient = DataSourcesClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._software_client: SoftwareClient = SoftwareClient(
            data_source=data_source,
            remove_fn=remove_revoked_deprecated,
            parse_fn=parse_stix_objects,
        )
        self._tactics_client: TacticsClient = TacticsClient(
            data_source=data_source,
            parse_fn=parse_stix_objects,
        )
        # Link detections client to techniques client for enrichment
        self._techniques_client.set_enrich_with_detections_fn(self._detections_client.enrich_techniques_with_detections)
        self._techniques_client.set_enrich_data_components_fn(self._detections_client.enrich_techniques_with_data_components)

        # Link techniques client to relationships client for enrichment
        self._relationships_client.set_get_techniques_fn(self._techniques_client.get_techniques)
        self._relationships_client.set_get_groups_fn(self._groups_client.get_groups)
        self._relationships_client.set_get_data_components_fn(self._data_sources_client.get_data_components)
        self._relationships_client.set_get_data_sources_fn(self._data_sources_client.get_data_sources)
        # Link analytics and data source clients to detections client for enrichment
        self._detections_client.set_get_analytics_by_ids_fn(self._analytics_client.get_analytics_by_ids)
        self._detections_client.set_get_data_components_by_ids_fn(self._data_sources_client.get_data_components_by_ids)

    @property
    def campaigns(self) -> CampaignsClient:
        """Return the campaigns client (cached)."""
        return self._campaigns_client

    @property
    def techniques(self) -> TechniquesClient:
        """Return the techniques client (cached)."""
        return self._techniques_client

    @property
    def mitigations(self) -> MitigationsClient:
        """Return the mitigations client (cached)."""
        return self._mitigations_client

    @property
    def analytics(self) -> AnalyticsClient:
        """Return the analytis client (cached)."""
        return self._analytics_client
    
    @property
    def detections(self) -> DetectionsClient:
        """Return the detections client (cached)."""
        return self._detections_client

    @property
    def groups(self) -> GroupsClient:
        """Return the groups client (cached)."""
        return self._groups_client

    @property
    def relationships(self) -> RelationshipsClient:
        """Return the relationships client (cached)."""
        return self._relationships_client

    @property
    def data_sources(self) -> DataSourcesClient:
        """Return the data sources client (cached)."""
        return self._data_sources_client

    @property
    def software(self) -> SoftwareClient:
        """Return the software client (cached)."""
        return self._software_client

    @property
    def tactics(self) -> TacticsClient:
        """Return the tactics client (cached)."""
        return self._tactics_client

    def get_object_by_attack_id(self, object_type: str, attack_id: str, *, stix_format: bool = True) -> list[Any]:
        """Return STIX objects by ATT&CK external id.

        Parameters
        ----------
        object_type
            STIX type to query (e.g., attack-pattern).
        attack_id
            ATT&CK external reference id (e.g., T1003).
        stix_format
            When `True`, return STIX objects/dicts; when `False`, parse to the
            mapped Pydantic model if available.

        Returns
        -------
        list[Any]
            Matching STIX objects in the requested format.

        Raises
        ------
        ValueError
            If an unsupported `object_type` is provided.
        """
        valid_objects = {
            "attack-pattern",
            "course-of-action",
            "intrusion-set",
            "malware",
            "tool",
            "x-mitre-data-source",
            "x-mitre-data-component",
            "campaign",
        }
        if object_type not in valid_objects:
            raise ValueError(f"ERROR: Valid object must be one of {valid_objects}")

        filter_objects = [Filter("type", "=", object_type), Filter("external_references.external_id", "=", attack_id)]
        all_stix_objects = self.data_source.query(filter_objects)
        if not stix_format:
            pydantic_model = pydantic_model_mapping.get(object_type)
            if pydantic_model:
                all_stix_objects = parse_stix_objects(all_stix_objects, pydantic_model)
        return all_stix_objects
