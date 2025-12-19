"""
MITRE ATT&CK Python Client.

This module provides a high-level client for accessing and interacting with MITRE ATT&CK data.
It includes support for querying data from local STIX bundles or the MITRE ATT&CK TAXII 2.1 server.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from pydantic import ValidationError

from .core.query_client import QueryClient
from .domains.enterprise import EnterpriseClient
from .domains.ics import ICSClient
from .domains.mobile import MobileClient
from .legacy import attach_legacy_methods
from .models import STIXLocalPaths
from .sources import MitreAttackSource
from .utils.downloader import STIXDownloader

# os.environ['http_proxy'] = "http://xxxxxxx"
# os.environ['https_proxy'] = "https://xxxxxxx"


class MitreAttackClient:
    """High-level client for accessing MITRE ATT&CK data."""
    
    def __init__(
        self,
        local_paths=None,
        proxies=None,
        verify=True,
        connect_taxii: bool = True,
        *,
        collection_url: str | None = None,
        attack_source: MitreAttackSource | None = None,
    ):
        """Initialize the ATT&CK client.

        Parameters
        ----------
        local_paths : dict[str, str] | None, optional
            Mapping of domain name to a local directory or JSON bundle path.
            Keys are typically ``enterprise``, ``mobile``, and ``ics``.
        proxies : dict | None, optional
            Requests proxy configuration for TAXII (when used).
        verify : bool, optional
            Whether to verify TLS certificates for TAXII requests.
        connect_taxii : bool, optional
            When `True`, allow TAXII initialization/fallback when local sources
            are missing. When `False`, do not perform any network calls.
        collection_url : str | None, optional
            Base TAXII collections URL (ending in ``/collections/``). If omitted,
            uses the MITRE default.
        attack_source : MitreAttackSource | None, optional
            Pre-loaded sources container. When provided, `local_paths` and
            `connect_taxii` are ignored and this container is used.

        Raises
        ------
        ValueError
            If `local_paths` is provided but fails validation.
        """
        self._connect_taxii = connect_taxii
        self._taxii_collection_url = collection_url
        self.mode: str = "empty"
        self.spec_version: str | None = None
        self._source_spec_versions: dict[str, str | None] = {}

        if attack_source is not None:
            self._init_from_source(attack_source)
            return

        # Validate local_paths with Pydantic
        if local_paths:
            try:
                self.local_paths = STIXLocalPaths(**local_paths)
            except ValidationError as e:
                raise ValueError(f"Invalid local_paths: {e}") from e

        # Initialize data sources
        self.init_data_sources(self.local_paths if local_paths else None, proxies, verify)

    def _init_from_source(self, sources: MitreAttackSource) -> None:
        """Populate client attributes from a pre-loaded source container.

        Parameters
        ----------
        sources : MitreAttackSource
            Container of loaded sources to attach to this client.
        """
        self.sources = sources
        self.TC_ENTERPRISE_SOURCE = sources.enterprise
        self.TC_MOBILE_SOURCE = sources.mobile
        self.TC_ICS_SOURCE = sources.ics
        self.COMPOSITE_DS = sources.composite
        self._source_spec_versions = sources.versions
        self.mode = sources.mode
        self.spec_version = sources.spec_version

    def init_data_sources(self, local_paths: STIXLocalPaths | None, proxies: dict | None, verify: bool) -> None:
        """Initialize the underlying domain sources.

        Parameters
        ----------
        local_paths : STIXLocalPaths | None
            Validated local paths to bundles/directories for each domain.
        proxies : dict | None
            Requests proxy configuration for TAXII (when used).
        verify : bool
            Whether to verify TLS certificates for TAXII requests.
        """
        enterprise = local_paths.enterprise if local_paths else None
        mobile = local_paths.mobile if local_paths else None
        ics = local_paths.ics if local_paths else None

        sources = MitreAttackSource.load(
            enterprise=enterprise,
            mobile=mobile,
            ics=ics,
            connect_taxii=self._connect_taxii,
            proxies=proxies,
            verify=verify,
            collection_url=self._taxii_collection_url,
        )
        self._init_from_source(sources)
    
    @classmethod
    def from_local(
        cls,
        *,
        enterprise: str | None = None,
        mobile: str | None = None,
        ics: str | None = None,
    ) -> "MitreAttackClient":
        """Create a client backed by local STIX bundles (STIX 2.0 or 2.1).

        Parameters
        ----------
        enterprise : str | None, optional
            Path to an enterprise STIX JSON file or directory of JSON files.
        mobile : str | None, optional
            Path to a mobile STIX JSON file or directory of JSON files.
        ics : str | None, optional
            Path to an ICS STIX JSON file or directory of JSON files.

        Returns
        -------
        MitreAttackClient
            Client initialized in local mode using the provided bundles.
        """
        source = MitreAttackSource.load(
            enterprise=enterprise,
            mobile=mobile,
            ics=ics,
            connect_taxii=False,
            proxies=None,
            verify=True,
            collection_url=None,
        )
        return cls(attack_source=source)

    @classmethod
    def from_attack_stix_data(
        cls,
        *,
        download_dir: str = ".attackcti/stix-2.1",
        release: str | None = None,
        domains: tuple[str, ...] = ("enterprise", "mobile", "ics"),
        pretty_print: bool = False,
        force_download: bool = False,
    ) -> "MitreAttackClient":
        """Download ATT&CK STIX 2.1 bundles and initialize the client from them.

        This is a convenience helper for the common workflow:
        download STIX bundles from `mitre-attack/attack-stix-data`, then load them
        in local mode.

        Parameters
        ----------
        download_dir : str, optional
            Root directory to store downloaded STIX bundles. Defaults to
            ``.attackcti/stix-2.1`` (relative to the current working directory).
        release : str | None, optional
            ATT&CK release to download (e.g., ``"18.1"``). When `None`, downloads
            the latest bundle files.
        domains : tuple[str, ...], optional
            Domains to download/load. Each value must be one of
            ``("enterprise", "mobile", "ics")``.
        pretty_print : bool, optional
            When `True`, rewrite downloaded JSON with indentation.
        force_download : bool, optional
            When `True`, always download even if a file exists in the target
            location. When `False`, reuse existing files if present.

        Returns
        -------
        MitreAttackClient
            Client initialized in local mode using the downloaded bundles.

        Raises
        ------
        ValueError
            If `domains` contains an unsupported value.
        """
        allowed = {"enterprise", "mobile", "ics"}
        unknown = [d for d in domains if d not in allowed]
        if unknown:
            raise ValueError(f"Unsupported domains: {unknown}. Valid domains are {sorted(allowed)}")

        expanded_dir = str(Path(download_dir).expanduser().resolve())
        downloader = STIXDownloader(download_dir=expanded_dir, stix_version="2.1")
        for domain in domains:
            downloader.download_attack_data(
                domain=domain,
                release=release,
                pretty_print=pretty_print,
                force=force_download,
            )

        return cls.from_local(
            enterprise=downloader.downloaded_file_paths.get("enterprise"),
            mobile=downloader.downloaded_file_paths.get("mobile"),
            ics=downloader.downloaded_file_paths.get("ics"),
        )

    @classmethod
    def from_taxii(
        cls,
        *,
        proxies: dict | None = None,
        verify: bool = True,
        collection_url: str | None = None,
    ) -> "MitreAttackClient":
        """Create a client backed by the MITRE ATT&CK TAXII 2.1 server.

        Parameters
        ----------
        proxies : dict | None, optional
            Requests proxy configuration.
        verify : bool, optional
            Whether to verify TLS certificates.
        collection_url : str | None, optional
            Base TAXII collections URL (ending in ``/collections/``). If omitted,
            uses the MITRE default.

        Returns
        -------
        MitreAttackClient
            Client initialized in TAXII mode.
        """
        source = MitreAttackSource.load(
            enterprise=None,
            mobile=None,
            ics=None,
            connect_taxii=True,
            proxies=proxies,
            verify=verify,
            collection_url=collection_url,
        )
        return cls(attack_source=source)

    def _get_cached_subclient(self, attr_name: str, cls: type) -> Any:
        """Return a lazily-created subclient stored on this client.

        Parameters
        ----------
        attr_name : str
            Attribute name to cache the client under.
        cls : type
            Subclient class to instantiate when missing.

        Returns
        -------
        Any
            Cached subclient instance.
        """
        cached = getattr(self, attr_name, None)
        if cached is None:
            cached = cls(self)
            setattr(self, attr_name, cached)
        return cached

    @property
    def enterprise(self) -> EnterpriseClient:
        """Return the EnterpriseClient instance (cached).

        Returns
        -------
        EnterpriseClient
            The client for interacting with enterprise-related data.
        """
        cached = getattr(self, "_enterprise_client", None)
        if cached is None:
            cached = EnterpriseClient(
                data_source=self.TC_ENTERPRISE_SOURCE,
            )
            self._enterprise_client = cached
        return cached

    @property
    def mobile(self) -> MobileClient:
        """Return the MobileClient instance (cached).

        Returns
        -------
        MobileClient
            The client for interacting with mobile-related data.
        """
        cached = getattr(self, "_mobile_client", None)
        if cached is None:
            cached = MobileClient(
                data_source=self.TC_MOBILE_SOURCE,
            )
            self._mobile_client = cached
        return cached

    @property
    def ics(self) -> ICSClient:
        """Return the ICSClient instance (cached).

        Returns
        -------
        ICSClient
            The client for interacting with ICS-related data.
        """
        cached = getattr(self, "_ics_client", None)
        if cached is None:
            cached = ICSClient(
                data_source=self.TC_ICS_SOURCE,
            )
            self._ics_client = cached
        return cached

    @property
    def query(self) -> QueryClient:
        """Return the QueryClient instance (cached).

        The QueryClient provides methods for querying and interacting with the
        composite data source, including enterprise, mobile, and ICS domains.

        Returns
        -------
        QueryClient
            The client for cross-domain queries.
        """
        cached = getattr(self, "_query_client", None)
        if cached is None:
            cached = QueryClient(
                self.COMPOSITE_DS,
            )
            self._query_client = cached
        return cached
    
    def get_attack(self, stix_format: bool = True) -> Dict[str, Dict]:
        """Return objects from enterprise, mobile, and ICS matrices.

        Parameters
        ----------
        stix_format : bool, optional
            When `True`, return STIX objects; when `False`, return parsed dicts
            based on the corresponding Pydantic models.

        Returns
        -------
        dict[str, dict]
            Mapping with keys ``enterprise``, ``mobile``, and ``ics`` containing
            the corresponding STIX objects (or parsed dicts).
        """
        attack_stix_objects = dict()
        attack_stix_objects['enterprise'] = self.enterprise.get_enterprise(stix_format)
        attack_stix_objects['mobile'] = self.mobile.get_mobile(stix_format)
        attack_stix_objects['ics'] = self.ics.get_ics(stix_format)

        return attack_stix_objects


attach_legacy_methods(MitreAttackClient)
