"""Initialization of the attackcti.core.objects module."""

from .analytics import AnalyticsClient
from .campaigns import CampaignsClient
from .data_sources import DataSourcesClient
from .detections import DetectionsClient
from .groups import GroupsClient
from .mitigations import MitigationsClient
from .relationships import RelationshipsClient
from .software import SoftwareClient
from .tactics import TacticsClient
from .techniques import TechniquesClient

__all__ = [
    "CampaignsClient",
    "DataSourcesClient",
    "AnalyticsClient",
    "DetectionsClient",
    "GroupsClient",
    "MitigationsClient",
    "RelationshipsClient",
    "SoftwareClient",
    "TacticsClient",
    "TechniquesClient",
]
