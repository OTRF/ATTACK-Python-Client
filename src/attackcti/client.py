"""ATT&CK client.

This module provides the main high-level interface for retrieving and querying MITRE ATT&CK
data via TAXII 2.1 or from locally cached STIX bundles.
"""

from stix2 import TAXIICollectionSource, Filter, CompositeDataSource
from stix2.datastore.filters import apply_common_filters
from taxii2client.v21 import Collection
import json
import os

from pydantic import BaseModel, TypeAdapter, ValidationError
from typing import List, Type, Dict, Any, Union
from .constants import (
    ATTACK_TAXII_COLLECTIONS_URL,
    ENTERPRISE_ATTACK_COLLECTION_ID,
    ICS_ATTACK_COLLECTION_ID,
    MOBILE_ATTACK_COLLECTION_ID,
)
from .models import (
    Campaign,
    DataComponent,
    DataSource,
    Group,
    Identity,
    MarkingDefinition,
    Matrix,
    Mitigation,
    Relationship,
    Software,
    STIXLocalPaths,
    Tactic,
    Technique,
)
from .utils.storage import STIXStore


# os.environ['http_proxy'] = "http://xxxxxxx"
# os.environ['https_proxy'] = "https://xxxxxxx"

class AttackClient:
    """High-level client for accessing MITRE ATT&CK data."""
    
    pydantic_model_mapping = {
        "techniques": Technique,
        "data-component": DataComponent,
        "mitigations": Mitigation,
        "groups": Group,
        "malware": Software,
        "tools": Software,
        "tool": Software,
        "data-source": DataSource,
        "relationships": Relationship,
        "tactics": Tactic,
        "matrix": Matrix,
        "identity": Identity,
        "marking-definition": MarkingDefinition,
        "campaigns": Campaign,
        "campaign": Campaign,
        "attack-pattern": Technique,
        "course-of-action": Mitigation,
        "intrusion-set": Group,
        "x-mitre-data-source": DataSource,
        "x-mitre-data-component": DataComponent
    }
    
    def __init__(self, local_paths=None, proxies=None, verify=True):
        """
        Initializes the ATT&CK client, setting up local or remote data sources.

        Args:
            local_paths (dict, optional): Dictionary with paths to local directories or JSON files for each domain.
                                          Keys should be 'enterprise', 'mobile', and 'ics'.
            proxies (dict, optional): Dictionary mapping protocol or protocol and hostname to the URL of the proxy.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """
        self.COMPOSITE_DS = CompositeDataSource()

        # Validate local_paths with Pydantic
        if local_paths:
            try:
                self.local_paths = STIXLocalPaths(**local_paths)
            except ValidationError as e:
                raise ValueError(f"Invalid local_paths: {e}")

        # Initialize data sources
        self.init_data_sources(self.local_paths if local_paths else None, proxies, verify)

    def init_data_sources(self, local_paths, proxies, verify):
        """
        Initializes data sources, either local or remote.

        Args:
            local_paths (LocalPathsModel, optional): Validated dictionary with paths to local directories or JSON files for each domain.
            proxies (dict, optional): Dictionary mapping protocol or protocol and hostname to the URL of the proxy.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """
        if local_paths:
            self.TC_ENTERPRISE_SOURCE = self.load_stix_store(local_paths.enterprise)
            self.TC_MOBILE_SOURCE = self.load_stix_store(local_paths.mobile)
            self.TC_ICS_SOURCE = self.load_stix_store(local_paths.ics)

            if not (self.TC_ENTERPRISE_SOURCE and self.TC_MOBILE_SOURCE and self.TC_ICS_SOURCE):
                self.initialize_taxii_sources(proxies, verify)
        else:
            self.initialize_taxii_sources(proxies, verify)

        self.COMPOSITE_DS.add_data_sources([self.TC_ENTERPRISE_SOURCE, self.TC_MOBILE_SOURCE, self.TC_ICS_SOURCE])

    def load_stix_store(self, path):
        """
        Loads a STIXStore from the given path.

        Args:
            path (str): Path to the source directory or JSON file.

        Returns:
            The loaded STIXStore or None if the path is invalid.
        """
        if path and os.path.exists(path):
            store = STIXStore(path)
            return store.get_store()
        return None

    def initialize_taxii_sources(self, proxies, verify):
        """
        Initializes data sources from the ATT&CK TAXII server.

        Args:
            proxies (dict, optional): Dictionary mapping protocol or protocol and hostname to the URL of the proxy.
            verify (bool, optional): Whether to verify SSL certificates. Defaults to True.
        """
        enterprise_url = f"{ATTACK_TAXII_COLLECTIONS_URL}{ENTERPRISE_ATTACK_COLLECTION_ID}/"
        mobile_url = f"{ATTACK_TAXII_COLLECTIONS_URL}{MOBILE_ATTACK_COLLECTION_ID}/"
        ics_url = f"{ATTACK_TAXII_COLLECTIONS_URL}{ICS_ATTACK_COLLECTION_ID}/"

        ENTERPRISE_COLLECTION = Collection(enterprise_url, verify=verify, proxies=proxies)
        MOBILE_COLLECTION = Collection(mobile_url, verify=verify, proxies=proxies)
        ICS_COLLECTION = Collection(ics_url, verify=verify, proxies=proxies)

        self.TC_ENTERPRISE_SOURCE = TAXIICollectionSource(ENTERPRISE_COLLECTION)
        self.TC_MOBILE_SOURCE = TAXIICollectionSource(MOBILE_COLLECTION)
        self.TC_ICS_SOURCE = TAXIICollectionSource(ICS_COLLECTION)
    
    def get_stix_objects(
        self, 
        source: TAXIICollectionSource, 
        filter_objects: Dict[str, Union[Filter, callable]], 
        stix_format: bool = True
    ) -> Dict[str, List]:
        """
        Retrieves STIX objects from the specified TAXII collection source based on the given filters or methods.
        Depending on the 'stix_format' flag, this function returns the STIX objects in their original format or 
        as parsed objects based on Pydantic models.

        Args:
            source (TAXIICollectionSource): The TAXII collection source to query for STIX objects.
            filter_objects (Dict[str, Union[Filter, Callable]]): A mapping of object types to their respective
                            TAXII filters or custom methods that return STIX objects.
            stix_format (bool, optional): If True, returns STIX objects in their original format. If False, returns the results
                                as parsed objects based on Pydantic models, providing a user-friendly representation.

        Returns:
            Dict[str, List]: A dictionary categorizing STIX objects by their types. Each key represents an object
            type (e.g., 'techniques', 'campaigns'), and each value is a list of STIX objects in their original format
            or parsed objects based on Pydantic models, depending on the 'stix_format' flag.
        """
        stix_objects_result = dict()
        for key, method_or_filter in filter_objects.items():
            if isinstance(method_or_filter, Filter):
                objects = source.query(method_or_filter)
            else:
                objects = method_or_filter()

            if not stix_format and hasattr(self, 'pydantic_model_mapping'):
                # Get the Pydantic model class for the current STIX object type
                pydantic_model = self.pydantic_model_mapping.get(key)
                # Parse the STIX objects using the appropriate Pydantic model
                if pydantic_model:
                    objects = self.parse_stix_objects(objects, pydantic_model)

            stix_objects_result[key] = objects

        return stix_objects_result

    def parse_stix_objects(self, stix_objects: List, model: Type[BaseModel]) -> List[Dict[str, Any]]:
        """
        Converts a list of STIX objects to dictionaries and parses them into the specified Pydantic model.

        Args:
            stix_objects (List): The list of STIX objects to parse.
            model (Type[BaseModel]): The Pydantic model class to use for parsing.

        Returns:
            List[Dict[str, Any]]: A list of dictionaries.
        """
        # Convert STIX objects to dictionaries
        objects_as_dicts = [json.loads(obj.serialize()) if not isinstance(obj, dict) else obj for obj in stix_objects]

        # Use TypeAdapter to validate and parse the dictionaries into Pydantic models
        type_adapter = TypeAdapter(List[model])
        parsed_objects = type_adapter.validate_python(objects_as_dicts)

        # Convert Pydantic models back to dictionaries for further use
        return [obj.model_dump() for obj in parsed_objects]

    def remove_revoked_deprecated(self, stix_objects: List) -> List:
        """
        Remove any revoked or deprecated objects from queries made to the data source.

        References:
        - https://github.com/mitre/cti/issues/127
        - https://github.com/mitre/cti/blob/master/USAGE.md#removing-revoked-and-deprecated-objects

        Args:
            stix_objects (List): List of STIX objects.

        Returns:
            List: List of STIX objects excluding revoked and deprecated ones.
        """
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False, stix_objects
            )
        )
    
    def extract_revoked(self, stix_objects: List) -> List:
        """
        Extract revoked objects from STIX objects.

        Reference:
        - https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html

        Args:
            stix_objects (List): List of STIX objects.

        Returns:
            List: List of revoked STIX objects.
        """
        return list(
            apply_common_filters(
                stix_objects,
                [Filter('revoked', '=', True)]
            )
        )
    
    def extract_deprecated(self, stix_objects: List) -> List:
        """
        Extract deprecated objects from STIX objects.

        Reference:
        - https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html

        Args:
            stix_objects (List): List of STIX objects.

        Returns:
            List: List of deprecated STIX objects.
        """
        return list(
            apply_common_filters(
                stix_objects,
                [Filter('x_mitre_deprecated', '=', True)]
            )
        )

    # ******** Enterprise ATT&CK Technology Domain  *******


# Attach method implementations from modules (no mixins / no inheritance).
from . import domains as _domains
from . import query as _query
from . import relationships as _relationships

for _module in (_domains, _query, _relationships):
    for _name in getattr(_module, "__all__", ()):
        setattr(AttackClient, _name, getattr(_module, _name))


# Backwards-compatible alias for older imports.
attack_client = AttackClient
