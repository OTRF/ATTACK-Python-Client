"""Local STIX bundle source helpers.

This module centralizes loading local STIX JSON bundles (files or directories)
into STIX2 data sources via `attackcti.utils.storage.STIXStore`.
"""

from __future__ import annotations

import os
from typing import Any

from ..utils.storage import STIXStore


def load_stix_store(path: str | None) -> tuple[Any | None, str | None]:
    """Load a STIX store from a directory or JSON file path.

    Args:
        path: Path to a directory of JSON files or a single STIX JSON file. If
            `None` or not found on disk, returns `(None, None)`.

    Returns
    -------
    tuple
        A `(source, spec_version)` tuple. If `path` is missing, returns
        `(None, None)`.
    """
    if path and os.path.exists(path):
        store = STIXStore(path)
        return store.get_store(), store.spec_version
    return None, None


def load_local_sources(
    *,
    enterprise: str | None = None,
    mobile: str | None = None,
    ics: str | None = None,
) -> tuple[tuple[Any | None, Any | None, Any | None], dict[str, str | None]]:
    """Load local sources for enterprise, mobile, and ICS.

    Args:
        enterprise: Path to the local enterprise bundle (dir or JSON file).
        mobile: Path to the local mobile bundle (dir or JSON file).
    
    Returns
    -------
    tuple
        `((enterprise_source, mobile_source, ics_source), versions)` where
        `versions` maps `enterprise|mobile|ics` to detected spec versions (or
        `None` when unavailable).
        `versions` maps `enterprise|mobile|ics` to detected spec versions (or
        `None` when unavailable).
    """
    enterprise_source, enterprise_ver = load_stix_store(enterprise)
    mobile_source, mobile_ver = load_stix_store(mobile)
    ics_source, ics_ver = load_stix_store(ics)

    versions = {
        "enterprise": enterprise_ver,
        "mobile": mobile_ver,
        "ics": ics_ver,
    }
    return (enterprise_source, mobile_source, ics_source), versions
