"""MITRE ATT&CK TAXII source helpers.

This module builds TAXII 2.1 collection sources for the MITRE ATT&CK datasets.
"""

from __future__ import annotations

from stix2 import TAXIICollectionSource
from taxii2client.v21 import Collection

from ..constants import (
    ATTACK_TAXII_COLLECTIONS_URL,
    ENTERPRISE_ATTACK_COLLECTION_ID,
    ICS_ATTACK_COLLECTION_ID,
    MOBILE_ATTACK_COLLECTION_ID,
)


def _normalize_collections_url(collections_url: str) -> str:
    """Normalize a TAXII collections base URL.

    Args:
        collections_url: Base URL for TAXII collections (typically ends with
            /collections/).

    Returns
    -------
        Normalized URL with a trailing /.

    Raises
    ------
    ValueError: If collections_url is empty after trimming whitespace.
    """
    collections_url = collections_url.strip()
    if not collections_url:
        raise ValueError("collection_url must be a non-empty string")
    if not collections_url.endswith("/"):
        collections_url += "/"
    return collections_url


def create_taxii_sources(
    *,
    proxies: dict | None = None,
    verify: bool = True,
    collection_url: str | None = None,
) -> tuple[TAXIICollectionSource, TAXIICollectionSource, TAXIICollectionSource]:
    """Create TAXII sources for enterprise, mobile, and ICS ATT&CK.

    Args:
        proxies: Requests proxy configuration passed to taxii2client (and
            ultimately requests).
        verify: Whether to verify TLS certificates.
        collection_url: Base collections URL (ending in /collections/). If
            omitted, uses :data:`attackcti.constants.ATTACK_TAXII_COLLECTIONS_URL`.

    Returns
    -------
        A tuple of sources for (enterprise, mobile, ics).

    Raises
    ------
    ValueError
        If collection_url is provided but empty.
    """
    collections_url = _normalize_collections_url(collection_url or ATTACK_TAXII_COLLECTIONS_URL)

    enterprise_url = f"{collections_url}{ENTERPRISE_ATTACK_COLLECTION_ID}/"
    mobile_url = f"{collections_url}{MOBILE_ATTACK_COLLECTION_ID}/"
    ics_url = f"{collections_url}{ICS_ATTACK_COLLECTION_ID}/"

    enterprise_collection = Collection(enterprise_url, verify=verify, proxies=proxies)
    mobile_collection = Collection(mobile_url, verify=verify, proxies=proxies)
    ics_collection = Collection(ics_url, verify=verify, proxies=proxies)

    return (
        TAXIICollectionSource(enterprise_collection),
        TAXIICollectionSource(mobile_collection),
        TAXIICollectionSource(ics_collection),
    )


def load_taxii_sources(
    *,
    proxies: dict | None = None,
    verify: bool = True,
    collection_url: str | None = None,
) -> tuple[tuple[TAXIICollectionSource, TAXIICollectionSource, TAXIICollectionSource], dict[str, str]]:
    """Load TAXII sources for enterprise, mobile, and ICS.

    Args:
        proxies: Requests proxy configuration passed to taxii2client.
        verify: Whether to verify TLS certificates.
        collection_url: Base collections URL (ending in /collections/). If
            omitted, uses :data:`attackcti.constants.ATTACK_TAXII_COLLECTIONS_URL`.
    
    Returns
    -------
        `((enterprise_source, mobile_source, ics_source), versions)` where
        `versions` maps `enterprise|mobile|ics` to `"2.1"`.
        `versions` maps `enterprise|mobile|ics` to `"2.1"`.

    Raises
    ------
        ValueError: If collection_url is provided but empty.
    """
    sources = create_taxii_sources(
        proxies=proxies,
        verify=verify,
        collection_url=collection_url,
    )
    versions = {
        "enterprise": "2.1",
        "mobile": "2.1",
        "ics": "2.1",
    }
    return sources, versions
