"""Cross-domain group query helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Union

from stix2 import CompositeDataSource, Filter
from stix2.v21.sdo import IntrusionSet as IntrusionSetV21

from ...models import Group as GroupModel


class GroupsClient:
    """Group query helper class."""

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

    def get_groups(self, *, skip_revoked_deprecated: bool = True, stix_format: bool = True) -> List[Union[IntrusionSetV21, Dict[str, Any]]]:
        """Return all intrusion-set groups across domains.

        Parameters
        ----------
        skip_revoked_deprecated
            When `True`, omit revoked/deprecated groups.
        stix_format
            When `True`, return STIX objects; when `False`, parse to the `Group`
            Pydantic model.

        Returns
        -------
        List[Union[IntrusionSetV21, Dict[str, Any]]]
            Intrusion-set group objects in the requested format.
        """
        groups = self._data_source.query([Filter("type", "=", "intrusion-set")])
        if skip_revoked_deprecated:
            groups = self._remove_fn(groups)
        if not stix_format:
            groups = self._parse_fn(groups, GroupModel)
        return groups


    def get_group_by_alias(self, alias: str, *, case: bool = True, stix_format: bool = True) -> List[Union[IntrusionSetV21, Dict[str, Any]]]:
        """Return groups matching a provided alias.

        Parameters
        ----------
        alias
            Alias to match.
        case
            When `True`, perform case-sensitive match; otherwise performs
            case-insensitive containment match.
        stix_format
            When `True`, return STIX objects; when `False`, parse to the `Group`
            Pydantic model.

        Returns
        -------
        List[Union[IntrusionSetV21, Dict[str, Any]]]
            Matching group objects in the requested format.
        """
        if not case:
            groups = self.get_groups(stix_format=True)
            out: list[Any] = []
            for group in groups:
                if "aliases" in group.keys():
                    for group_alias in group["aliases"]:
                        if alias.lower() in group_alias.lower():
                            out.append(GroupModel)
        else:
            filter_objects = [Filter("type", "=", "intrusion-set"), Filter("aliases", "=", alias)]
            out = self._data_source.query(filter_objects)
        if not stix_format:
            out = self._parse_fn(out, GroupModel)
        return out
