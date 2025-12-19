"""Cross-domain mitigation query helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Union

from stix2 import CompositeDataSource, Filter
from stix2.v21.sdo import CourseOfAction as CourseOfActionV21

from ...models import Mitigation as MitigationModel


class MitigationsClient:
    """Mitigation query helper class."""

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

    def get_mitigations(self, *, skip_revoked_deprecated: bool = True, stix_format: bool = True) -> List[Union[CourseOfActionV21, Dict[str, Any]]]:
        """Return course-of-action mitigations across domains.

        Parameters
        ----------
        skip_revoked_deprecated : bool, optional
            When `True`, omit revoked/deprecated mitigations.
        stix_format : bool, optional
            When `True`, return STIX objects/dicts; when `False`, parse to the
            `Mitigation` Pydantic model.

        Returns
        -------
        list[CourseOfActionV21 | dict[str, Any]]
            Mitigation objects in the requested format.
        """
        all_mitigations = self._data_source.query([Filter("type", "=", "course-of-action")])
        if skip_revoked_deprecated:
            all_mitigations = self._remove_fn(all_mitigations)
        if not stix_format:
            all_mitigations = self._parse_fn(all_mitigations, MitigationModel)
        return all_mitigations
