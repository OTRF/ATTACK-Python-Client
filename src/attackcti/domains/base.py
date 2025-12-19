"""Shared domain client implementation."""

from __future__ import annotations

from typing import Any, Dict

from stix2 import CompositeDataSource, Filter, MemorySource, TAXIICollectionSource

from ..core.query_client import QueryClient
from ..models import pydantic_model_mapping


def _filter_software_by_type(items: list[Any], *, stix_type: str) -> list[Any]:
    """Return software objects matching a specific STIX type."""
    out: list[Any] = []
    for item in items:
        if isinstance(item, dict):
            if item.get("type") == stix_type:
                out.append(item)
        else:
            item_type = getattr(item, "type", None)
            if item_type == stix_type:
                out.append(item)
    return out


class DomainClientBase:
    """Base class for domain-scoped clients (enterprise/mobile/ics)."""

    def __init__(
        self,
        *,
        data_source: TAXIICollectionSource | MemorySource | None,
    ) -> None:
        self.data_source = data_source
        if self.data_source is None:
            raise RuntimeError("domain source is not loaded")
        # Set up a composite data source.
        composite = CompositeDataSource()
        # Add the domain-specific data source.
        composite.add_data_sources([self.data_source])
        # Initialize the query client.
        self._query_client = QueryClient(composite, pydantic_map=pydantic_model_mapping)

    def get(self, stix_format: bool = True) -> dict[str, list[Any]]:
        """Return a bundle of common ATT&CK objects for the domain."""
        return {
            "techniques": self.get_techniques(stix_format=stix_format),
            "data-component": self.get_data_components(stix_format=stix_format),
            "mitigations": self.get_mitigations(stix_format=stix_format),
            "groups": self.get_groups(stix_format=stix_format),
            "malware": self.get_malware(stix_format=stix_format),
            "tools": self.get_tools(stix_format=stix_format),
            "data-source": self.get_data_sources(stix_format=stix_format),
            "relationships": self.get_relationships(stix_format=stix_format),
            "tactics": self.get_tactics(stix_format=stix_format),
            "matrix": self.data_source.query(Filter("type", "=", "x-mitre-matrix")),
            "identity": self.data_source.query(Filter("type", "=", "identity")),
            "marking-definition": self.data_source.query(Filter("type", "=", "marking-definition")),
            "campaigns": self.get_campaigns(stix_format=stix_format),
        }

    # Domain-scoped wrappers that delegate to the core query helpers.

    def get_techniques(self, stix_format: bool = True) -> list[Any]:
        """Return techniques for this domain."""
        return self._query_client.techniques.get_techniques(stix_format=stix_format)

    def get_data_components(self, stix_format: bool = True) -> list[Dict[str, Any]]:
        """Return data components for this domain."""
        return self._query_client.data_sources.get_data_components(stix_format=stix_format)

    def get_mitigations(self, stix_format: bool = True) -> list[Any]:
        """Return mitigations for this domain."""
        return self._query_client.mitigations.get_mitigations(stix_format=stix_format)

    def get_groups(self, stix_format: bool = True) -> list[Any]:
        """Return intrusion-set groups for this domain."""
        return self._query_client.groups.get_groups(stix_format=stix_format)

    def get_malware(self, stix_format: bool = True) -> list[Any]:
        """Return malware for this domain."""
        software = self._query_client.software.get_software(stix_format=stix_format)
        return _filter_software_by_type(software, stix_type="malware")

    def get_tools(self, stix_format: bool = True) -> list[Any]:
        """Return tools for this domain."""
        software = self._query_client.software.get_software(stix_format=stix_format)
        return _filter_software_by_type(software, stix_type="tool")

    def get_data_sources(self, stix_format: bool = True) -> list[Dict[str, Any]]:
        """Return data sources for this domain."""
        return self._query_client.data_sources.get_data_sources(stix_format=stix_format)

    def get_relationships(self, stix_format: bool = True) -> list[Any]:
        """Return relationships for this domain."""
        return self._query_client.relationships.get_relationships(stix_format=stix_format)

    def get_tactics(self, stix_format: bool = True) -> list[Dict[str, Any]]:
        """Return tactics for this domain."""
        return self._query_client.tactics.get_tactics(stix_format=stix_format)

    def get_campaigns(self, stix_format: bool = True) -> list[Any]:
        """Return campaigns for this domain."""
        return self._query_client.campaigns.get_campaigns(stix_format=stix_format)
