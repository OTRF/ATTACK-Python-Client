"""Enterprise ATT&CK domain client."""

from __future__ import annotations

from stix2 import MemorySource, TAXIICollectionSource

from .base import DomainClientBase


class EnterpriseClient(DomainClientBase):
    """Enterprise-domain client."""

    def __init__(
        self,
        *,
        data_source: TAXIICollectionSource | MemorySource | None,
    ) -> None:
        super().__init__(
            data_source=data_source,
        )

    def get_enterprise(self, stix_format: bool = True) -> dict[str, list[object]]:
        """Alias for `get` to preserve older naming."""
        return self.get(stix_format=stix_format)