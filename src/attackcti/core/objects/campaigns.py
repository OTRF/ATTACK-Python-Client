"""Cross-domain campaign query helpers."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Union

from stix2 import CompositeDataSource, Filter
from stix2.v21.sdo import Campaign as CampaignV21

from ...models import Campaign as CampaignModel


class CampaignsClient:
    """Campaigns query helper class."""

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

    def get_campaigns(self, *, skip_revoked_deprecated: bool = True, stix_format: bool = True) -> List[Union[CampaignV21, Dict[str, Any]]]:
        """Return campaigns across ATT&CK matrices.

        Parameters
        ----------
        skip_revoked_deprecated
            When `True`, omit revoked/deprecated campaigns.
        stix_format
            When `True`, return STIX objects; when `False`, parse to the
            `Campaign` Pydantic model.

        Returns
        -------
        List[Union[CampaignV21, Dict[str, Any]]]
            Campaign objects in the requested format.
        """
        all_campaigns = self._data_source.query([Filter("type", "=", "campaign")])
        if skip_revoked_deprecated:
            all_campaigns = self._remove_fn(all_campaigns)
        if not stix_format:
            all_campaigns = self._parse_fn(all_campaigns, CampaignModel)
        return all_campaigns


    def get_campaign_by_alias(self, *, alias: str, case: bool = True, stix_format: bool = True) -> List[Union[CampaignV21, Dict[str, Any]]]:
        """Return campaigns that match a provided alias.

        Parameters
        ----------
        alias
            Alias to match.
        case
            When `True`, perform case-sensitive match; otherwise performs
            case-insensitive containment match.
        stix_format
            When `True`, return STIX objects; when `False`, parse to the
            `Campaign` Pydantic model.

        Returns
        -------
        List[Union[CampaignV21, Dict[str, Any]]]
            Matching campaign objects in the requested format.
        """
        if not case:
            all_campaigns = self.get_campaigns(stix_format=True)
            out: list[Any] = []
            for campaign in all_campaigns:
                if "aliases" in campaign.keys():
                    for campaign_alias in campaign["aliases"]:
                        if alias.lower() in campaign_alias.lower():
                            out.append(CampaignModel)
        else:
            filter_objects = [Filter("type", "=", "campaign"), Filter("aliases", "contains", alias)]
            out = self._data_source.query(filter_objects)

        if not stix_format:
            out = self._parse_fn(out, CampaignModel)
        return out


    def get_campaigns_since_time(self, *, timestamp: str, stix_format: bool = True) -> List[Union[CampaignV21, Dict[str, Any]]]:
        """Return campaigns created after the provided timestamp.

        Parameters
        ----------
        timestamp
            Timestamp string for filtering.
        stix_format
            When `True`, return STIX objects; when `False`, parse to the
            `Campaign` Pydantic model.

        Returns
        -------
        List[Union[CampaignV21, Dict[str, Any]]]
            Campaign objects in the requested format.
        """
        filter_objects = [Filter("type", "=", "campaign"), Filter("created", ">", timestamp)]
        out = self._data_source.query(filter_objects)
        if not stix_format:
            out = self._parse_fn(out, CampaignModel)
        return out
