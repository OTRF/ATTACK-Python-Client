"""Source selection helpers.

This module contains the policy for combining multiple source types (local STIX
bundles and TAXII) into the final set of domain sources used by the client.
"""

from __future__ import annotations

from typing import Any

from .local_loader import load_local_sources
from .taxii_loader import load_taxii_sources


def load_sources(
    *,
    enterprise: str | None = None,
    mobile: str | None = None,
    ics: str | None = None,
    connect_taxii: bool = True,
    proxies: dict | None = None,
    verify: bool = True,
    collection_url: str | None = None,
) -> tuple[tuple[Any | None, Any | None, Any | None], dict[str, str | None], str, str | None]:
    """Load sources using a local-first policy with optional TAXII fallback.

    Policy:
      - If local sources exist, use them.
      - If some local domains are missing and `connect_taxii=True`, fill missing domains from TAXII.
      - If no local sources exist:
          - If `connect_taxii=True`, load all domains from TAXII.
          - If `connect_taxii=False`:
              - Raise if the caller provided local paths (they were invalid).
              - Otherwise return an empty configuration.

    Args:
        enterprise: Path to the local enterprise bundle (dir or JSON file).
        mobile: Path to the local mobile bundle (dir or JSON file).
        ics: Path to the local ICS bundle (dir or JSON file).
        connect_taxii: If `True`, allow TAXII fallback/fill behavior.
        proxies: Requests proxy configuration for TAXII.
        verify: Whether to verify TLS certificates for TAXII.
        collection_url: Base TAXII collections URL (ending in `/collections/`).

    Returns
    -------
    tuple
        A tuple `(sources, versions, mode, spec_version)` where:
        - `sources` is `(enterprise_source, mobile_source, ics_source)`
        - `versions` maps `enterprise|mobile|ics` to spec versions (or `None`)
        - `mode` is one of `local`, `taxii`, `mixed`, `empty`
        - `spec_version` is the unified spec version if known, else `None`

    Raises
    ------
        ValueError: If local paths were provided but none were loadable and
            `connect_taxii=False`.
    """
    local_paths_provided = any((enterprise, mobile, ics))

    (enterprise_source, mobile_source, ics_source), versions = load_local_sources(
        enterprise=enterprise,
        mobile=mobile,
        ics=ics,
    )

    any_local = any((enterprise_source, mobile_source, ics_source))
    if not any_local:
        if not connect_taxii:
            if local_paths_provided:
                raise ValueError("No valid local data sources found.")
            return (None, None, None), {"enterprise": None, "mobile": None, "ics": None}, "empty", None

        (enterprise_source, mobile_source, ics_source), versions = load_taxii_sources(
            proxies=proxies,
            verify=verify,
            collection_url=collection_url,
        )
        return (enterprise_source, mobile_source, ics_source), versions, "taxii", "2.1"

    missing_any = any(ds is None for ds in (enterprise_source, mobile_source, ics_source))
    if missing_any and connect_taxii:
        (taxii_enterprise, taxii_mobile, taxii_ics), taxii_versions = load_taxii_sources(
            proxies=proxies,
            verify=verify,
            collection_url=collection_url,
        )
        if enterprise_source is None:
            enterprise_source = taxii_enterprise
            versions["enterprise"] = taxii_versions["enterprise"]
        if mobile_source is None:
            mobile_source = taxii_mobile
            versions["mobile"] = taxii_versions["mobile"]
        if ics_source is None:
            ics_source = taxii_ics
            versions["ics"] = taxii_versions["ics"]
        mode = "mixed"
    else:
        mode = "local"

    non_null_versions = {v for v in versions.values() if v is not None}
    spec_version = non_null_versions.pop() if len(non_null_versions) == 1 else None
    return (enterprise_source, mobile_source, ics_source), versions, mode, spec_version
