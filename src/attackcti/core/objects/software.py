"""Cross-domain software query helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Union

from stix2 import CompositeDataSource, Filter
from stix2.v21.sdo import Malware as MalwareV21
from stix2.v21.sdo import Tool as ToolV21

from ...models import Software
from ...utils.stix import parse_stix_objects, remove_revoked_deprecated


class SoftwareClient:
    """Software (malware/tool) query helper class."""

    def __init__(
        self,
        *,
        data_source: CompositeDataSource,
        remove_fn: Callable = remove_revoked_deprecated,
        parse_fn: Callable = parse_stix_objects,
    ) -> None:
        """Initialize the client with a composite data source."""
        self._data_source = data_source
        self._remove_fn = remove_fn
        self._parse_fn = parse_fn

    def get_software(self, *, skip_revoked_deprecated: bool = True, stix_format: bool = True) -> List[Union[MalwareV21, ToolV21, Dict[str, Any]]]:
        """Return malware and tool software objects across domains.

        Parameters
        ----------
        skip_revoked_deprecated : bool, optional
            When `True`, omit revoked/deprecated software.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, parse to the
            `Software` Pydantic model.

        Returns
        -------
        list[MalwareV21 | ToolV21 | dict[str, Any]]
            Software objects in the requested format.
        """
        all_software = self._data_source.query([Filter("type", "in", ["malware", "tool"])])
        if skip_revoked_deprecated:
            all_software = self._remove_fn(all_software)
        if not stix_format:
            all_software = self._parse_fn(all_software, Software)
        return all_software
    
    def get_malware(
        self,
        *,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> list[MalwareV21 | dict[str, Any]]:
        """Return malware software objects across domains.

        Parameters
        ----------
        skip_revoked_deprecated : bool, optional
            When `True`, omit revoked/deprecated malware.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, parse to the
            `Software` Pydantic model.

        Returns
        -------
        list[MalwareV21 | dict[str, Any]]
            Malware objects in the requested format.
        """
        malware = self._data_source.query(Filter("type", "=", "malware"))
        if skip_revoked_deprecated:
            malware = self._remove_fn(malware)
        if not stix_format:
            malware = self._parse_fn(malware, Software)
        return malware

    def get_tools(
        self,
        *,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True,
    ) -> list[ToolV21 | dict[str, Any]]:
        """Return tool software objects across domains.

        Parameters
        ----------
        skip_revoked_deprecated : bool, optional
            When `True`, omit revoked/deprecated tools.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, parse to the
            `Software` Pydantic model.

        Returns
        -------
        list[ToolV21 | dict[str, Any]]
            Tool objects in the requested format.
        """
        tools = self._data_source.query(Filter("type", "=", "tool"))
        if skip_revoked_deprecated:
            tools = self._remove_fn(tools)
        if not stix_format:
            tools = self._parse_fn(tools, Software)
        return tools
