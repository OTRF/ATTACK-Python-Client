"""Cross-domain data source/component helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, Iterable, List
from warnings import warn

from stix2 import CompositeDataSource, Filter

from ...models import DataComponent as DataComponentModel
from ...models import DataSource as DataSourceModel


class DataSourcesClient:
    """Data source and data component queries."""

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        remove_fn: Callable | None = None,
        parse_fn: Callable | None = None,
    ) -> None:
        """Initialize the client with a composite data source."""
        self._data_source = data_source
        self._remove_fn = remove_fn
        self._parse_fn = parse_fn

    def get_data_components(self, *, skip_revoked_deprecated: bool = True, stix_format: bool = True) -> List[Dict[str, Any]]:
        """Return data components across all domains.

        Parameters
        ----------
        skip_revoked_deprecated
            When `True`, omit revoked/deprecated data components.
        stix_format
            When `True`, return STIX objects; when `False`, parse to the
            `DataComponent` Pydantic model.

        Returns
        -------
        List[Dict[str, Any]]
            Data component objects in the requested format.
        """
        all_data_components = self._data_source.query([Filter("type", "=", "x-mitre-data-component")])
        if skip_revoked_deprecated:
            all_data_components = self._remove_fn(all_data_components)
        if not stix_format:
            all_data_components = self._parse_fn(all_data_components, DataComponentModel)
        return all_data_components
    
    def get_data_sources(self, *, include_data_components: bool = False, stix_format: bool = True) -> List[Dict[str, Any]]:
        """Return data sources across all domains.

        Parameters
        ----------
        include_data_components
            When `True`, enrich data sources with related data components
            (requires Pydantic parsing).
        stix_format
            When `True`, return STIX objects; when `False`, parse to the
            `DataSource` Pydantic model.

        Returns
        -------
        List[Dict[str, Any]]
            Data source objects in the requested format.
        """
        warn(
            "Data Sources (`x-mitre-data-source`) are deprecated as of ATT&CK Specification 3.3.0. "
            "Data Sources are superseded by the Detection Strategy framework..",
            DeprecationWarning,
            stacklevel=2,
        )
        all_data_sources = self._data_source.query([Filter("type", "=", "x-mitre-data-source")])
        all_data_sources = self._remove_fn(all_data_sources)
        if include_data_components:
            all_data_sources = self._parse_fn(all_data_sources, DataSourceModel, include_data_components=True)
        elif not stix_format:
            all_data_sources = self._parse_fn(all_data_sources, DataSourceModel)
        return all_data_sources
    
    def get_data_components_by_ids(
        self,
        ids: Iterable[str],
        *,
        stix_format: bool = True,
        data_components: list[dict[str, Any]] | None = None,
        skip_revoked_deprecated: bool = True,
    ) -> list[dict[str, Any]]:
        """Return data component objects for the requested ids."""
        dc_ids = {did for did in ids if isinstance(did, str) and did}
        if not dc_ids:
            return []

        if data_components is None:
            data_components = self.get_data_components(
                skip_revoked_deprecated=skip_revoked_deprecated,
                stix_format=True,
            )

        selected = [dc for dc in data_components if dc.get("id") in dc_ids]
        if not stix_format:
            return self._parse_fn(selected, DataComponentModel)
        return selected
