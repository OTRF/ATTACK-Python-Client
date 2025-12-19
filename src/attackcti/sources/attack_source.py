"""Wrapper that encapsulates loaded ATT&CK data sources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from stix2 import CompositeDataSource

from .resolver import load_sources


@dataclass
class MitreAttackSource:
    """Container for ATT&CK STIX sources.

    Attributes
    ----------
    enterprise
        Domain-scoped source for Enterprise ATT&CK (or None if not loaded).
    mobile
        Domain-scoped source for Mobile ATT&CK (or None if not loaded).
    ics
        Domain-scoped source for ICS ATT&CK (or None if not loaded).
    composite
        `CompositeDataSource` containing all loaded domain sources.
    versions
        Mapping of domain -> spec version (or None).
    mode
        One of local, taxii, mixed, empty.
    spec_version
        Unified spec version if all domains match, else None.
    """

    enterprise: Any | None
    mobile: Any | None
    ics: Any | None
    composite: CompositeDataSource
    versions: dict[str, str | None]
    mode: str
    spec_version: str | None

    @classmethod
    def load(
        cls,
        *,
        enterprise: str | None = None,
        mobile: str | None = None,
        ics: str | None = None,
        connect_taxii: bool = True,
        proxies: dict | None = None,
        verify: bool = True,
        collection_url: str | None = None,
    ) -> "MitreAttackSource":
        """Load ATT&CK sources and return a container."""
        (ent, mob, ics_src), versions, mode, spec_version = load_sources(
            enterprise=enterprise,
            mobile=mobile,
            ics=ics,
            connect_taxii=connect_taxii,
            proxies=proxies,
            verify=verify,
            collection_url=collection_url,
        )
        composite = CompositeDataSource()
        composite.add_data_sources([ds for ds in (ent, mob, ics_src) if ds is not None])
        return cls(
            enterprise=ent,
            mobile=mob,
            ics=ics_src,
            composite=composite,
            versions=versions,
            mode=mode,
            spec_version=spec_version,
        )
