#!/usr/bin/env python

# ATT&CK Client Main Script
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: BSD 3-Clause
# Reference:
# https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via
# https://github.com/mitre/cti/blob/master/USAGE.md
# https://github.com/oasis-open/cti-python-stix2/issues/183
# https://stackoverflow.com/a/4406521

from stix2 import TAXIICollectionSource, Filter, CompositeDataSource
from stix2.datastore.filters import apply_common_filters
from stix2.utils import get_type_from_id
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21, # Technique
    Campaign as Campaign_v21, # Campaign
    Malware as Malware_v21, # Malware
    CourseOfAction as CourseOfAction_v21, # Mitigation
    IntrusionSet as IntrusionSet_v21, # Group
    Tool as Tool_v21 # Tool
)
from stix2.v21.sro import Relationship as Relationship_v21
from taxii2client.v21 import Collection
import json
import os

from pydantic import TypeAdapter, ValidationError
from typing import List, Type, Dict, Any, Union
from attackcti.models import *
from attackcti.utils.storage import STIXStore

# os.environ['http_proxy'] = "http://xxxxxxx"
# os.environ['https_proxy'] = "https://xxxxxxx"

ATTACK_STIX_COLLECTIONS = "https://attack-taxii.mitre.org/api/v21/collections/"
ENTERPRISE_ATTACK = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019"
MOBILE_ATTACK = "x-mitre-collection--dac0d2d7-8653-445c-9bff-82f934c1e858"
ICS_ATTACK = "x-mitre-collection--90c00720-636b-4485-b342-8751d232bf09"

class attack_client:
    """A Python Module for accessing ATT&CK data locally or remotely."""
    
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
        ENTERPRISE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + ENTERPRISE_ATTACK + "/", verify=verify, proxies=proxies)
        MOBILE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + MOBILE_ATTACK + "/", verify=verify, proxies=proxies)
        ICS_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + ICS_ATTACK + "/", verify=verify, proxies=proxies)

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
    def get_enterprise(self, stix_format: bool = True) -> Dict[str, List]:
        """
        Extracts all available STIX objects from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        the function either returns STIX objects in their original format or as parsed objects represented as dictionaries.

        Args:
            stix_format (bool, optional): If True, returns results in the original STIX format. If False, returns the results
                                        in a parsed and user-friendly format as dictionaries, structured according to the Pydantic model's schema.

        Returns:
            Dict[str, List]: A dictionary categorizing STIX objects by their types. Each key represents an object
            type (e.g., 'techniques', 'campaigns'), and each value is a list of STIX objects in their original format
            or as dictionaries representing the parsed data, depending on the 'stix_format' flag.
        """
        enterprise_filter_objects = {
            "techniques": self.get_enterprise_techniques,
            "data-component": self.get_enterprise_data_components,
            "mitigations": self.get_enterprise_mitigations,
            "groups": self.get_enterprise_groups,
            "malware": self.get_enterprise_malware,
            "tools": self.get_enterprise_tools,
            "data-source": self.get_enterprise_data_sources,
            "relationships": self.get_enterprise_relationships,
            "tactics": self.get_enterprise_tactics,
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition"),
            "campaigns": self.get_enterprise_campaigns
        }

        return self.get_stix_objects(self.TC_ENTERPRISE_SOURCE, enterprise_filter_objects, stix_format)

    def get_enterprise_campaigns(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[Campaign_v21, Dict[str, Any]]]:
        """
        Extracts all available campaigns from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated campaign objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns campaign objects in their original STIX format. If False,
                                        returns campaigns as custom dictionaries parsed according to the Campaign Pydantic model.
                                        Default is True.

        Returns:
            List[Union[Campaign_v21, Dict[str, Any]]]: A list of campaign objects, either as STIX objects (Campaign_v21) 
                or as custom dictionaries following the structure defined by the Campaign Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_campaigns = self.TC_ENTERPRISE_SOURCE.query([Filter("type", "=", "campaign")])

        if skip_revoked_deprecated:
            enterprise_campaigns = self.remove_revoked_deprecated(enterprise_campaigns)
        
        if not stix_format:
            enterprise_campaigns = self.parse_stix_objects(enterprise_campaigns, Campaign)
        
        return enterprise_campaigns

    def get_enterprise_techniques(
        self, 
        skip_revoked_deprecated: bool = True, 
        include_subtechniques: bool = True, 
        enrich_data_sources: bool = False, 
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Extracts all available techniques from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models. It can also include sub-techniques and add data component and
        data source context to each technique if specified.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            include_subtechniques (bool, optional): If True, includes both techniques and sub-techniques in the results.
                                                    Default is True.
            enrich_data_sources (bool, optional): If True, adds data component and data source context to each technique.
                                                Default is False.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """  
        if include_subtechniques:
            enterprise_techniques = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        else:
            enterprise_techniques = self.TC_ENTERPRISE_SOURCE.query([
                Filter("type", "=", "attack-pattern"),
                Filter('x_mitre_is_subtechnique', '=', False)
            ])

        if skip_revoked_deprecated:
            enterprise_techniques = self.remove_revoked_deprecated(enterprise_techniques)

        if enrich_data_sources:
            enterprise_techniques = self.enrich_techniques_data_sources(enterprise_techniques)
        
        if not stix_format:
            enterprise_techniques = self.parse_stix_objects(enterprise_techniques, Technique)
        
        return enterprise_techniques

    def get_enterprise_data_components(self, stix_format: bool = True) -> List[Dict[str,Any]]:
        """
        Extracts all available data components from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function returns a list of dictionaries in their original STIX format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns data component objects in their original STIX format. If False,
                                        returns data components as custom dictionaries parsed according to the
                                        DataComponent Pydantic model. Default is True.

        Returns:
            List[Dict[str, Any]]: A list of data component objects as dictionaries following the structure
                defined STIX or the DataComponent Pydantic model, depending on the 'stix_format' flag.
        """
        enterprise_data_components = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        if not stix_format:
            enterprise_data_components = self.parse_stix_objects(enterprise_data_components, DataComponent)
        return enterprise_data_components

    def get_enterprise_mitigations(self, stix_format: bool = True) -> List[Union[CourseOfAction_v21, Dict[str, Any]]]:
        """
        Extracts all available mitigations from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns mitigation objects in their original STIX format. If False,
                                        returns mitigations as custom dictionaries parsed according to the Mitigation
                                        Pydantic model. Default is True.

        Returns:
            List[Union[CourseOfAction_v21, Dict[str, Any]]]: A list of mitigation objects, either as STIX objects (CourseOfAction_v21)
                or as custom dictionaries following the structure defined by the Mitigation Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_mitigations = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            enterprise_mitigations = self.parse_stix_objects(enterprise_mitigations, Mitigation)
        return enterprise_mitigations
    
    def get_enterprise_groups(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format:bool =True
    ) -> List[Union[IntrusionSet_v21, Dict[str, Any]]]:
        """
        Extracts all available groups from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated group objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns group objects in their original STIX format. If False,
                                        returns groups as custom dictionaries parsed according to the Group Pydantic model.
                                        Default is True.

        Returns:
            List[Union[IntrusionSet_v21, Dict[str, Any]]]: A list of group objects, either as STIX objects (IntrusionSet_v21)
                or as custom dictionaries following the structure defined by the Group Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_groups = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            enterprise_groups = self.remove_revoked_deprecated(enterprise_groups)
        
        if not stix_format:
            enterprise_groups = self.parse_stix_objects(enterprise_groups, Group)
        return enterprise_groups
    
    def get_enterprise_malware(self, stix_format: bool = True) -> List[Union[Malware_v21, Dict[str, Any]]]:
        """
        Extracts all available malware from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns malware objects in their original STIX format. If False,
                                        returns malware objects as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Malware_v21, Dict[str, Any]]]: A list of malware objects, either as STIX objects (Malware_v21)
                or as custom dictionaries following the structure defined by the Software Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_malware = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            enterprise_malware = self.parse_stix_objects(enterprise_malware, Software)
        return enterprise_malware
    
    def get_enterprise_tools(self, stix_format: bool = True) -> List[Union[Tool_v21, Dict[str, Any]]]:
        """
        Extracts all available tools from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tool objects in their original STIX format. If False,
                                        returns tools as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Tool_v21, Dict[str, Any]]]: A list of tool objects, either as STIX objects (Tool_v21)
                or as custom dictionaries following the structure defined by the Software Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_tools = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            enterprise_tools = self.parse_stix_objects(enterprise_tools, Software)
        return enterprise_tools
    
    def get_enterprise_relationships(self, stix_format: bool = True) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """
        Extracts all available relationships from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns relationship objects in their original STIX format. If False,
                                        returns relationships as custom dictionaries parsed according to the Relationship
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Relationship_v21, Dict[str, Any]]]: A list of relationship objects, either as STIX objects (Relationship_v21)
                or as custom dictionaries following the structure defined by the Relationship Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_relationships = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            enterprise_relationships = self.parse_stix_objects(enterprise_relationships, Relationship)
        return enterprise_relationships
    
    def get_enterprise_tactics(self, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Extracts all available tactics from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tactics objects in their original STIX format. If False,
                                        returns tactics as custom objects parsed according to the Tactic Pydantic model.
                                        Default is True.

        Returns:
            List[Dict[str, Any]]: A list of tactic objects, either as dictionaries following the original STIX structure
                or defined by the Tactic Pydantic model, depending on the 'stix_format' flag.
        """
        enterprise_tactics = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            enterprise_tactics = self.parse_stix_objects(enterprise_tactics, Tactic)
        return enterprise_tactics
    
    def get_enterprise_data_sources(
        self,
        include_data_components: bool = False,
        stix_format: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Extracts all available data sources from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models. It can also include related data components if specified.

        Args:
            include_data_components (bool, optional): If True, includes related data components in the results.
                                                    Default is False.
            stix_format (bool, optional): If True, returns data source objects in their original STIX format. If False,
                                        returns data sources as custom objects parsed according to the DataSources
                                        Pydantic model. Default is True.

        Returns:
            List: A list of data source objects, either as dictionaries following the original STIX structure
                or defined by the DataSource Pydantic model, depending on the 'stix_format' flag.
        """
        enterprise_data_sources = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-data-source"))
        if include_data_components:
            for ds in enterprise_data_sources:
                ds['data_components']= self.get_data_components_by_data_source(ds)
        if not stix_format:
            enterprise_data_sources = self.parse_stix_objects(enterprise_data_sources, DataSource)
        return enterprise_data_sources

    # ******** Mobile ATT&CK Technology Domain  *******
    def get_mobile(self, stix_format: bool = True) -> Dict[str, List]:
        """
        Extracts all available STIX objects from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        the function either returns STIX objects in their original format or as parsed objects represented as dictionaries.

        Args:
            stix_format (bool, optional): If True, returns results in the original STIX format. If False, returns the results
                                        in a parsed and user-friendly format as dictionaries, structured according to the
                                        Pydantic model's schema.

        Returns:
            Dict[str, List]: A dictionary categorizing STIX objects by their types. Each key represents an object
            type (e.g., 'techniques', 'campaigns'), and each value is a list of STIX objects in their original format
            or as dictionaries representing the parsed data, depending on the 'stix_format' flag.
        """
        mobile_filter_objects = {
            "techniques": self.get_mobile_techniques,
            "data-component": self.get_mobile_data_components,
            "mitigations": self.get_mobile_mitigations,
            "groups": self.get_mobile_groups,
            "malware": self.get_mobile_malware,
            "tools": self.get_mobile_tools,
            "data-source": self.get_mobile_data_sources,
            "relationships": self.get_mobile_relationships,
            "tactics": self.get_mobile_tactics,
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition"),
            "campaigns": self.get_mobile_campaigns
        }
    
        return self.get_stix_objects(self.TC_MOBILE_SOURCE, mobile_filter_objects, stix_format)

    def get_mobile_campaigns(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[Campaign_v21, Dict[str, Any]]]:
        """
        Extracts all available campaigns from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated campaign objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns campaign objects in their original STIX format. If False,
                                        returns campaigns as custom dictionaries parsed according to the Campaign
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Campaign_v21, Dict[str, Any]]]: A list of campaign objects, either as STIX objects (Campaign_v21) 
                or as custom dictionaries following the structure defined by the Campaign Pydantic model, depending
                on the 'stix_format' flag.
        """
        mobile_campaigns = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "campaign"))

        if skip_revoked_deprecated:
            mobile_campaigns = self.remove_revoked_deprecated(mobile_campaigns)

        if not stix_format:
            mobile_campaigns = self.parse_stix_objects(mobile_campaigns, Campaign)
        return mobile_campaigns

    def get_mobile_techniques(
        self, 
        skip_revoked_deprecated: bool = True, 
        include_subtechniques: bool = True, 
        enrich_data_sources: bool = False, 
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Extracts all available techniques from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models. It can also include sub-techniques and add data component and
        data source context to each technique if specified.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            include_subtechniques (bool, optional): If True, includes both techniques and sub-techniques in the results.
                                                    Default is True.
            enrich_data_sources (bool, optional): If True, adds data component and data source context to each technique.
                                                Default is False.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if include_subtechniques:
            mobile_techniques = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        else:
            mobile_techniques = self.TC_MOBILE_SOURCE.query([
                Filter("type", "=", "attack-pattern"),
                Filter('x_mitre_is_subtechnique', '=', False)
            ])

        if skip_revoked_deprecated:
            mobile_techniques = self.remove_revoked_deprecated(mobile_techniques)
        
        if enrich_data_sources:
            mobile_techniques = self.enrich_techniques_data_sources(mobile_techniques)

        if not stix_format:
            mobile_techniques = self.parse_stix_objects(mobile_techniques, Technique)
        return mobile_techniques
    
    def get_mobile_data_components(self, stix_format: bool = True) -> List[Dict[str,Any]]:
        """
        Extracts all available data components from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns data component objects in their original STIX format. If False,
                                        returns data components as custom dictionaries parsed according to the DataComponent
                                        Pydantic model. Default is True.

        Returns:
            List[Dict[str, Any]]: A list of data component objects as dictionaries following the structure
                defined STIX or the DataComponent Pydantic model, depending on the 'stix_format' flag.
        """
        mobile_data_components = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        if not stix_format:
            mobile_data_components = self.parse_stix_objects(mobile_data_components, DataComponent)
        return mobile_data_components
    
    def get_mobile_mitigations(self, stix_format: bool = True) -> List[Union[CourseOfAction_v21, Dict[str, Any]]]:
        """
        Extracts all available mitigations from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns mitigation objects in their original STIX format. If False,
                                        returns mitigations as custom dictionaries parsed according to the Mitigation
                                        Pydantic model. Default is True.

        Returns:
            List[Union[CourseOfAction_v21, Dict[str, Any]]]: A list of mitigation objects, either as STIX objects (CourseOfAction_v21)
                or as custom dictionaries following the structure defined by the Mitigation Pydantic model, depending
                on the 'stix_format' flag.
        """
        mobile_mitigations = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            mobile_mitigations = self.parse_stix_objects(mobile_mitigations, Mitigation)
        return mobile_mitigations

    def get_mobile_groups(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format:bool =True
    ) -> List[Union[IntrusionSet_v21, Dict[str, Any]]]:
        """
        Extracts all available groups from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated group objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns group objects in their original STIX format. If False,
                                        returns groups as custom dictionaries parsed according to the Group Pydantic model.
                                        Default is True.

        Returns:
            List[Union[IntrusionSet_v21, Dict[str, Any]]]: A list of group objects, either as STIX objects (IntrusionSet_v21)
                or as custom dictionaries following the structure defined by the Group Pydantic model, depending
                on the 'stix_format' flag.
        """
        mobile_groups = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            mobile_groups = self.remove_revoked_deprecated(mobile_groups)
          
        if not stix_format:
            mobile_groups = self.parse_stix_objects(mobile_groups, Group)
        return mobile_groups
    
    def get_mobile_malware(self, stix_format: bool = True) -> List[Union[Malware_v21, Dict[str, Any]]]:
        """
        Extracts all available malware from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns malware objects in their original STIX format. If False,
                                        returns malware objects as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Malware_v21, Dict[str, Any]]]: A list of malware objects, either as STIX objects (Malware_v21)
                or as custom dictionaries following the structure defined by the Software Pydantic model, depending
                on the 'stix_format' flag.
        """
        mobile_malware = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            mobile_malware = self.parse_stix_objects(mobile_malware, Software)
        return mobile_malware
    
    def get_mobile_tools(self, stix_format: bool = True) -> List[Union[Tool_v21, Dict[str, Any]]]:
        """
        Extracts all available tools from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tool objects in their original STIX format. If False,
                                        returns tools as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Tool_v21, Dict[str, Any]]]: A list of tool objects, either as STIX objects (Tool_v21)
                or as custom dictionaries following the structure defined by the Software Pydantic model, depending
                on the 'stix_format' flag.
        """
        mobile_tools = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            mobile_tools = self.parse_stix_objects(mobile_tools, Software)
        return mobile_tools

    def get_mobile_relationships(self, stix_format: bool = True) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """
        Extracts all available relationships from the Enterprise ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns relationship objects in their original STIX format. If False,
                                        returns relationships as custom dictionaries parsed according to the Relationship
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Relationship_v21, Dict[str, Any]]]: A list of relationship objects, either as STIX objects (Relationship_v21)
                or as custom dictionaries following the structure defined by the Relationship Pydantic model, depending
                on the 'stix_format' flag.
        """
        mobile_relationships = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            mobile_relationships = self.parse_stix_objects(mobile_relationships, Relationship)
        return mobile_relationships
    
    def get_mobile_tactics(self, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Extracts all available tactics from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tactics objects in their original STIX format. If False,
                                        returns tactics as custom objects parsed according to the Tactic Pydantic model.
                                        Default is True.

        Returns:
            List[Dict[str, Any]]: A list of tactic objects, either as dictionaries following the original STIX structure
                or defined by the Tactic Pydantic model, depending on the 'stix_format' flag.
        """
        mobile_tactics = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            mobile_tactics = self.parse_stix_objects(mobile_tactics, Tactic)
        return mobile_tactics

    def get_mobile_data_sources(
        self,
        include_data_components: bool = False,
        stix_format: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Extracts all available data sources from the Mobile ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models. It can also include related data components if specified.

        Args:
            include_data_components (bool, optional): If True, includes related data components in the results.
                                                    Default is False.
            stix_format (bool, optional): If True, returns data source objects in their original STIX format. If False,
                                        returns data sources as custom objects parsed according to the DataSources
                                        Pydantic model. Default is True.

        Returns:
            List: A list of data source objects, either as dictionaries following the original STIX structure
                or defined by the DataSource Pydantic model, depending on the 'stix_format' flag.
        """
        mobile_data_sources = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "x-mitre-data-source"))
        if include_data_components:
            for ds in mobile_data_sources:
                ds['data_components']= self.get_data_components_by_data_source(ds)
        if not stix_format:
            mobile_data_sources = self.parse_stix_objects(mobile_data_sources, DataSource)
        return mobile_data_sources
    
    # ******** ICS ATT&CK Technology Domain *******
    def get_ics(self, stix_format: bool = True) -> Dict[str, List]:
        """
        Extracts all available STIX objects from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        the function either returns STIX objects in their original format or as parsed objects represented as dictionaries.

        Args:
            stix_format (bool, optional): If True, returns results in the original STIX format. If False, returns the results
                                        in a parsed and user-friendly format as dictionaries, structured according to the Pydantic model's schema.

        Returns:
            Dict[str, List]: A dictionary categorizing STIX objects by their types. Each key represents an object
            type (e.g., 'techniques', 'campaigns'), and each value is a list of STIX objects in their original format
            or as dictionaries representing the parsed data, depending on the 'stix_format' flag.
        """
        ics_filter_objects = {
            "techniques": self.get_ics_techniques,
            "data-component": self.get_ics_data_components,
            "mitigations": self.get_ics_mitigations,
            "groups": self.get_ics_groups,
            "malware": self.get_ics_malware,
            "tools": self.get_ics_tools,
            "data-source": self.get_ics_data_sources,
            "relationships": self.get_ics_relationships,
            "tactics": self.get_ics_tactics,
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition"),
            "campaigns": self.get_ics_campaigns
        }

        return self.get_stix_objects(self.TC_ICS_SOURCE, ics_filter_objects, stix_format)

    def get_ics_campaigns(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[Campaign_v21, Dict[str, Any]]]:
        """
        Extracts all available campaigns from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated campaign objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns campaign objects in their original STIX format. If False,
                                        returns campaigns as custom dictionaries parsed according to the Campaign
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Campaign_v21, Dict[str, Any]]]: A list of campaign objects, either as STIX objects (Campaign_v21) 
                or as custom dictionaries following the structure defined by the Campaign Pydantic model, depending
                on the 'stix_format' flag.
        """
        ics_campaigns = self.TC_ICS_SOURCE.query(Filter("type", "=", "campaign"))

        if skip_revoked_deprecated:
            ics_campaigns = self.remove_revoked_deprecated(ics_campaigns)

        if not stix_format:
            ics_campaigns = self.parse_stix_objects(ics_campaigns, Campaign)
        return ics_campaigns

    def get_ics_techniques(
        self, 
        skip_revoked_deprecated: bool = True, 
        include_subtechniques: bool = True, 
        enrich_data_sources: bool = False, 
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Extracts all available techniques from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models. It can also include sub-techniques and add data component and
        data source context to each technique if specified.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            include_subtechniques (bool, optional): If True, includes both techniques and sub-techniques in the results.
                                                    Default is True.
            enrich_data_sources (bool, optional): If True, adds data component and data source context to each technique.
                                                Default is False.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if include_subtechniques:
            ics_techniques = self.TC_ICS_SOURCE.query(Filter("type", "=", "attack-pattern"))
        else:
            ics_techniques = self.TC_ICS_SOURCE.query([
                Filter("type", "=", "attack-pattern"),
                Filter('x_mitre_is_subtechnique', '=', False)
            ])

        if skip_revoked_deprecated:
            ics_techniques = self.remove_revoked_deprecated(ics_techniques)
        
        if enrich_data_sources:
            ics_techniques = self.enrich_techniques_data_sources(ics_techniques)
        
        if not stix_format:
            ics_techniques = self.parse_stix_objects(ics_techniques, Technique)
        return ics_techniques

    def get_ics_data_components(self, stix_format: bool = True) -> List[Dict[str,Any]]:
        """
        Extracts all available data components from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns data component objects in their original STIX format. If False,
                                        returns data components as custom dictionaries parsed according to the DataComponent
                                        Pydantic model. Default is True.

        Returns:
            List[Dict[str, Any]]: A list of data component objects as dictionaries following the structure
                defined STIX or the DataComponent Pydantic model, depending on the 'stix_format' flag.
        """
        ics_data_components = self.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        if not stix_format:
            ics_data_components = self.parse_stix_objects(ics_data_components, DataComponent)
        return ics_data_components

    def get_ics_mitigations(self, stix_format: bool = True) -> List[Union[CourseOfAction_v21, Dict[str, Any]]]:
        """
        Extracts all available mitigations from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns mitigation objects in their original STIX format. If False,
                                        returns mitigations as custom dictionaries parsed according to the Mitigation
                                        Pydantic model. Default is True.

        Returns:
            List[Union[CourseOfAction_v21, Dict[str, Any]]]: A list of mitigation objects, either as STIX objects (CourseOfAction_v21)
                or as custom dictionaries following the structure defined by the Mitigation Pydantic model, depending
                on the 'stix_format' flag.
        """
        ics_mitigations = self.TC_ICS_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            ics_mitigations = self.parse_stix_objects(ics_mitigations, Mitigation)
        return ics_mitigations

    def get_ics_groups(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format:bool =True
    ) -> List[Union[IntrusionSet_v21, Dict[str, Any]]]:
        """
        Extracts all available groups from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated group objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns group objects in their original STIX format. If False,
                                        returns groups as custom dictionaries parsed according to the Group Pydantic model.
                                        Default is True.

        Returns:
            List[Union[IntrusionSet_v21, Dict[str, Any]]]: A list of group objects, either as STIX objects (IntrusionSet_v21)
                or as custom dictionaries following the structure defined by the Group Pydantic model, depending
                on the 'stix_format' flag.
        """
        ics_groups = self.TC_ICS_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            ics_groups = self.remove_revoked_deprecated(ics_groups)
        
        if not stix_format:
            ics_groups = self.parse_stix_objects(ics_groups, Group)
        return ics_groups

    def get_ics_malware(self, stix_format: bool = True) -> List[Union[Malware_v21, Dict[str, Any]]]:
        """
        Extracts all available malware from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns malware objects in their original STIX format. If False,
                                        returns malware objects as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Malware_v21, Dict[str, Any]]]: A list of malware objects, either as STIX objects (Malware_v21)
                or as custom dictionaries following the structure defined by the Software Pydantic model, depending
                on the 'stix_format' flag.
        """
        ics_malware = self.TC_ICS_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            ics_malware = self.parse_stix_objects(ics_malware, Software)
        return ics_malware

    def get_ics_tools(self, stix_format: bool = True) -> List[Union[Tool_v21, Dict[str, Any]]]:
        """
        Extracts all available tools from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tool objects in their original STIX format. If False,
                                        returns tools as custom dictionaries parsed according to the Software Pydantic model.
                                        Default is True.

        Returns:
            List[Union[Tool_v21, Dict[str, Any]]]: A list of tool objects, either as STIX objects (Tool_v21)
                or as custom dictionaries following the structure defined by the Software Pydantic model, depending
                on the 'stix_format' flag.
        """
        ics_tools = self.TC_ICS_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            ics_tools = self.parse_stix_objects(ics_tools, Software)
        return ics_tools

    def get_ics_relationships(self, stix_format: bool = True) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """
        Extracts all available relationships from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns relationship objects in their original STIX format. If False,
                                        returns relationships as custom dictionaries parsed according to the Relationship
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Relationship_v21, Dict[str, Any]]]: A list of relationship objects, either as STIX objects (Relationship_v21)
                or as custom dictionaries following the structure defined by the Relationship Pydantic model, depending
                on the 'stix_format' flag.
        """
        ics_relationships = self.TC_ICS_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            ics_relationships = self.parse_stix_objects(ics_relationships, Relationship)
        return ics_relationships
    
    def get_ics_tactics(self, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Extracts all available tactics from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tactics objects in their original STIX format. If False,
                                        returns tactics as custom objects parsed according to the Tactic Pydantic model.
                                        Default is True.

        Returns:
            List[Dict[str, Any]]: A list of tactic objects, either as dictionaries following the original STIX structure
                or defined by the Tactic Pydantic model, depending on the 'stix_format' flag.
        """
        ics_tactics = self.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            ics_tactics = self.parse_stix_objects(ics_tactics, Tactic)
        return ics_tactics

    def get_ics_data_sources(
        self,
        include_data_components: bool = False,
        stix_format: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Extracts all available data sources from the ICS ATT&CK matrix. Depending on the 'stix_format' flag,
        this function either returns a list of STIX objects in their original format or as parsed objects (Dictionaries)
        following a structure defined by Pydantic models. It can also include related data components if specified.

        Args:
            include_data_components (bool, optional): If True, includes related data components in the results.
                                                    Default is False.
            stix_format (bool, optional): If True, returns data source objects in their original STIX format. If False,
                                        returns data sources as custom objects parsed according to the DataSources
                                        Pydantic model. Default is True.

        Returns:
            List: A list of data source objects, either as dictionaries following the original STIX structure
                or defined by the DataSource Pydantic model, depending on the 'stix_format' flag.
        """
        ics_data_sources = self.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-data-source"))
        if include_data_components:
            for ds in ics_data_sources:
                ds['data_components']= self.get_data_components_by_data_source(ds)
        if not stix_format:
            ics_data_sources = self.parse_stix_objects(ics_data_sources, DataSource)
        return ics_data_sources

    # ******** Get All Functions ********
    def get_attack(self, stix_format: bool = True) -> Dict[str, Dict]:
        """
        Aggregates STIX objects from different ATT&CK matrices (Enterprise, Mobile, ICS) into a single dictionary. 
        Depending on the 'stix_format' flag, this function can return STIX objects in their original format or as 
        parsed objects following structures defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns STIX objects in their original format. If False,
                                        returns parsed objects according to their respective Pydantic models.
                                        Default is True.

        Returns:
            Dict[str, Dict]: A dictionary with keys representing the ATT&CK matrix categories (e.g., 'enterprise', 
                            'mobile', 'ics') and values being the corresponding STIX objects or parsed objects, 
                            depending on the 'stix_format' flag.
        """
        attack_stix_objects = dict()
        attack_stix_objects['enterprise'] = self.get_enterprise(stix_format)
        attack_stix_objects['mobile'] = self.get_mobile(stix_format)
        attack_stix_objects['ics'] = self.get_ics(stix_format)
        
        return attack_stix_objects

    def get_campaigns(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[Campaign_v21, Dict[str, Any]]]:
        """
        Extracts all available campaign STIX objects across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending on 
        the 'stix_format' flag, this function either returns STIX objects in their original format or as parsed objects 
        (Dictionaries) following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated campaign objects. 
                                                    Default is True.
            stix_format (bool, optional): If True, returns campaign objects in their original STIX format. If False,
                                        returns campaigns as custom dictionaries parsed according to the Campaign 
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Campaign_v21, Dict[str, Any]]]: A list of campaign objects, either as STIX objects (Campaign_v21) 
                or as custom dictionaries following the structure defined by the Campaign Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_campaigns = self.get_enterprise_campaigns()
        mobile_campaigns = self.get_mobile_campaigns()
        ics_campaigns = self.get_ics_campaigns()
        for c in mobile_campaigns + ics_campaigns:
            if c not in enterprise_campaigns:
                enterprise_campaigns.append(c)

        if skip_revoked_deprecated:
            enterprise_campaigns = self.remove_revoked_deprecated(enterprise_campaigns)

        if not stix_format:
            enterprise_campaigns = self.parse_stix_objects(enterprise_campaigns, Campaign)

        return enterprise_campaigns

    def get_techniques(
        self, 
        skip_revoked_deprecated: bool = True, 
        include_subtechniques: bool = True, 
        enrich_data_sources: bool = False, 
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Extracts all available techniques from across all ATT&CK matrices (Enterprise, Mobile, ICS).
        This function can filter the techniques to include or exclude sub-techniques, remove revoked
        and deprecated entries, enrich the data with additional data source context, and return the data
        in either the original STIX format or a friendly parsed format.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            include_subtechniques (bool, optional): If True, includes both techniques and sub-techniques in the results.
                                                    Default is True.
            enrich_data_sources (bool, optional): If True, enriches each technique with data component and data source
                                                context. Default is False.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique 
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if include_subtechniques:
            all_techniques = self.COMPOSITE_DS.query(Filter("type", "=", "attack-pattern"))
        else:
            all_techniques = self.COMPOSITE_DS.query([
                Filter("type", "=", "attack-pattern"),
                Filter('x_mitre_is_subtechnique', '=', False)
            ])

        if skip_revoked_deprecated:
            all_techniques = self.remove_revoked_deprecated(all_techniques)

        if enrich_data_sources:
            all_techniques = self.enrich_techniques_data_sources(all_techniques)

        if not stix_format:
            all_techniques = self.parse_stix_objects(all_techniques, Technique)

        return all_techniques
    
    def get_groups(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format:bool =True
    ) -> List[Union[IntrusionSet_v21, Dict[str, Any]]]:
        """
        Extracts all available groups from across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending
        on the 'stix_format' flag, this function either returns a list of STIX objects in their original 
        format or as parsed objects (Dictionaries) following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated group objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns group objects in their original STIX format. If False,
                                        returns groups as custom dictionaries parsed according to the Group Pydantic model.
                                        Default is True.

        Returns:
            List[Union[IntrusionSet_v21, Dict[str, Any]]]: A list of group objects, either as STIX objects (IntrusionSet_v21)
                or as custom dictionaries following the structure defined by the Group Pydantic model, depending
                on the 'stix_format' flag.
        """
        all_groups = self.COMPOSITE_DS.query(Filter("type", "=", "intrusion-set"))
        
        if skip_revoked_deprecated:
            all_groups = self.remove_revoked_deprecated(all_groups)
        
        if not stix_format:
            all_groups = self.parse_stix_objects(all_groups, Group)
        return all_groups
   
    def get_mitigations(
        self,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[CourseOfAction_v21, Dict[str, Any]]]:
        """
        Extracts all available mitigations from across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending
        on the 'stix_format' flag, this function either returns a list of STIX objects in their original 
        format or as parsed objects (Dictionaries) following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated mitigation objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns mitigation objects in their original STIX format. If False,
                                        returns mitigations as custom dictionaries parsed according to the Mitigation Pydantic model.
                                        Default is True.

        Returns:
            List[Union[CourseOfAction_v21, Dict[str, Any]]]: A list of mitigation objects, either as STIX objects (CourseOfAction_v21)
                or as custom dictionaries following the structure defined by the Mitigation Pydantic model, depending
                on the 'stix_format' flag.
        """
        enterprise_mitigations = self.get_enterprise_mitigations()
        mobile_mitigations = self.get_mobile_mitigations()
        ics_mitigations = self.get_ics_mitigations()
        for mm in mobile_mitigations:
            if mm not in enterprise_mitigations:
                enterprise_mitigations.append(mm)
        for im in ics_mitigations:
            if im not in enterprise_mitigations:
                enterprise_mitigations.append(im)
        
        if skip_revoked_deprecated:
            enterprise_mitigations = self.remove_revoked_deprecated(enterprise_mitigations)
        
        if not stix_format:
            enterprise_mitigations = self.parse_stix_objects(enterprise_mitigations, Mitigation)
        return enterprise_mitigations

    def get_data_components(self, skip_revoked_deprecated: bool = True, stix_format: bool = True) -> List[Dict[str,Any]]:
        """
        Extracts all available data components from across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending
        on the 'stix_format' flag, this function either returns a list of STIX objects in their original 
        format or as parsed objects (Dictionaries) following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated data component objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns data component objects in their original STIX format. If False,
                                        returns data components as custom dictionaries parsed according to the DataComponent
                                        Pydantic model. Default is True.

        Returns:
            List[Dict[str, Any]]: A list of data component objects as dictionaries following the structure
                defined STIX or the DataComponent Pydantic model, depending on the 'stix_format' flag.
        """
        enterprise_data_components = self.get_enterprise_data_components()
        ics_data_components = self.get_ics_data_components()
        mobile_data_components = self.get_mobile_data_components()
        for mdc in mobile_data_components:
            if mdc not in enterprise_data_components:
                enterprise_data_components.append(mdc)
        for idc in ics_data_components:
            if idc not in enterprise_data_components:
                enterprise_data_components.append(idc)
        
        if skip_revoked_deprecated:
            enterprise_data_components = self.remove_revoked_deprecated(enterprise_data_components)
        
        if not stix_format:
            enterprise_data_components = self.parse_stix_objects(enterprise_data_components, DataComponent)
        return enterprise_data_components

    def get_software(
        self, skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[Malware_v21, Tool_v21, Dict[str, Any]]]:
        """
        Extracts all available software from across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending
        on the 'stix_format' flag, this function either returns a list of STIX objects in their original 
        format or as parsed objects (Dictionaries) following a structure defined by Pydantic models.

        Args:
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated software objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns software objects in their original STIX format. If False,
                                        returns software as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Malware_v21, Tool_v21, Dict[str, Any]]]: A list of software objects, either as 
                STIX objects (Malware_v21 or Tool_v21) or as custom dictionaries following the structure defined
                by the Software Pydantic model, depending on the 'stix_format' flag.
        """
        enterprise_malware = self.get_enterprise_malware()
        enterprise_tools = self.get_enterprise_tools()
        mobile_malware = self.get_mobile_malware()
        mobile_tools = self.get_mobile_tools()
        ics_malware = self.get_ics_malware()
        for mt in mobile_tools:
            if mt not in enterprise_tools:
                enterprise_tools.append(mt)
        for mmal in mobile_malware:
            if mmal not in enterprise_malware:
                enterprise_malware.append(mmal)
        for imal in ics_malware:
            if imal not in enterprise_malware:
                enterprise_malware.append(imal)
        all_software = enterprise_tools + enterprise_malware

        if skip_revoked_deprecated:
            all_software = self.remove_revoked_deprecated(all_software)
        
        if not stix_format:
            all_software = self.parse_stix_objects(all_software, Software)
        return all_software
   
    def get_relationships(
        self, relationship_type: str = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """
        Extracts STIX relationship objects across all ATT&CK matrices (Enterprise, Mobile, ICS), optionally filtered by a
        specific relationship type. Depending on the 'stix_format' flag, this function either returns a list of STIX objects
        in their original format or as parsed objects (Dictionaries) following a structure defined by Pydantic models.

        Args:
            relationship_type (str, optional): Type of relationship to filter (e.g., 'uses', 'mitigates', 'subtechnique-of', 
                                                'detects', 'revoked-by'). If None, all relationship types are returned. 
                                                Reference: https://github.com/mitre/cti/blob/master/USAGE.md#relationships
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated relationship objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns relationship objects in their original STIX format. If False,
                                        returns relationships as custom dictionaries parsed according to a Pydantic model
                                        that corresponds to the relationship type. Default is True.

        Returns:
            List[Union[Relationship_v21, Dict[str, Any]]]: A list of relationship objects, either as STIX objects (Relationship_v21)
                or as custom dictionaries following the structure defined by the Relationship Pydantic model, depending
                on the 'stix_format' flag.
        """
        if relationship_type:
            relationship_types = ['uses', 'mitigates', 'subtechnique-of', 'detects', 'revoked-by']
            if relationship_type not in relationship_types:
                raise ValueError(f"ERROR: Valid relationship types must be one of {relationship_types}")
            else:
                all_relationships = self.COMPOSITE_DS.query(
                    Filter("type", "=", "relationship"),
                    Filter("relationship_type", "=", relationship_type)
                )
        else:
            all_relationships = self.COMPOSITE_DS.query(Filter("type", "=", "relationship"))
        
        if skip_revoked_deprecated:
            all_relationships = self.remove_revoked_deprecated(all_relationships)
        
        if not stix_format:
            all_relationships = self.parse_stix_objects(all_relationships, Relationship)

        return all_relationships
    
    def get_tactics(self, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Extracts all available tactics from across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending on
        the 'stix_format' flag, this function either returns a list of STIX objects in their original format or
        as parsed objects (Dictionaries) following a structure defined by Pydantic models.

        Args:
            stix_format (bool, optional): If True, returns tactics objects in their original STIX format. If False,
                                        returns tactics as custom dictionaries parsed according to the Tactic Pydantic model.
                                        Default is True.

        Returns:
            List[Dict[str, Any]]: A list of tactic objects, either as dictionaries following the original STIX structure
                or defined by the Tactic Pydantic model, depending on the 'stix_format' flag.
        """
        all_tactics = self.COMPOSITE_DS.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            all_tactics = self.parse_stix_objects(all_tactics, Tactic)
        return all_tactics
    
    def get_data_sources(
        self, include_data_components: bool = False,
        stix_format: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Extracts all available data sources from across all ATT&CK matrices (Enterprise, Mobile, ICS). Depending on
        the 'stix_format' flag, this function either returns data sources in their original STIX format or as parsed
        objects (Dictionaries) following a structure defined by Pydantic models. It also optionally includes data components
        for each data source.

        Args:
            include_data_components (bool, optional): If True, includes data components related to each data source.
                                                    Default is False.
            stix_format (bool, optional): If True, returns data sources in their original STIX format. If False,
                                        returns data sources as custom dictionaries parsed according to the DataSource
                                        Pydantic model. Default is True.

        Returns:
            List: A list of data source objects, either as dictionaries following the original STIX structure
                or defined by the DataSource Pydantic model, depending on the 'stix_format' flag.
        """
        enterprise_data_sources = self.get_enterprise_data_sources(include_data_components)
        ics_data_sources = self.get_ics_data_sources(include_data_components)
        mobile_data_sources = self.get_mobile_data_sources(include_data_components)
        for mds in mobile_data_sources:
            if mds not in enterprise_data_sources:
                enterprise_data_sources.append(mds)
        for ids in ics_data_sources:
            if ids not in enterprise_data_sources:
                enterprise_data_sources.append(ids)

        if not stix_format:
            enterprise_data_sources = self.parse_stix_objects(enterprise_data_sources, DataSource)

        return enterprise_data_sources

    # ******** Custom Functions ********
    def get_technique_by_name(
        self,
        name: str,
        case: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Searches and retrieves the technique STIX object(s) by name across all ATT&CK matrices. The search can be case-sensitive
        or case-insensitive, and the results can be returned in the original STIX format or a friendly syntax.

        Args:
            name (str): The name of the technique to search for.
            case (bool, optional): Determines if the search should be case sensitive (True) or case insensitive (False).
                                Default is True.
            stix_format (bool, optional): If True, returns the technique object in its original STIX format. If False,
                                        returns the technique as a custom dictionary parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if not case:
            all_techniques = self.get_techniques()
            matched_techniques = []
            for tech in all_techniques:
                if name.lower() in tech['name'].lower():
                    matched_techniques.append(tech)
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('name', '=', name)
            ]
            matched_techniques = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            matched_techniques = self.parse_stix_objects(matched_techniques, Technique)
        return matched_techniques
    
    def get_techniques_by_content(
        self,
        content: str,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Searches and retrieves technique STIX objects containing the specified content in their descriptions across all ATT&CK matrices,
        using a case-insensitive search.

        Args:
            content (str): The content to search for within the technique descriptions.
            stix_format (bool, optional): If True, returns techniques in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        all_techniques = self.get_techniques()
        matched_techniques = []

        for tech in all_techniques:
            description = tech.get('description', '').lower()
            if content.lower() in description:
                matched_techniques.append(tech)

        if not stix_format:
            matched_techniques = self.parse_stix_objects(matched_techniques, Technique)

        return matched_techniques

    
    def get_techniques_by_platform(
        self, name: str,
        case: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves techniques STIX objects associated with a specific platform across all ATT&CK matrices. 
        The search can be case-sensitive or case-insensitive.

        Args:
            name (str): The name of the platform to search for within the technique's platform.
            case (bool, optional): Determines if the search should be case sensitive. Default is True.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if not case:
            all_techniques = self.get_techniques()
            matched_techniques = []
            for tech in all_techniques:
                if 'x_mitre_platforms' in tech.keys():
                    for platform in tech['x_mitre_platforms']:
                        if name.lower() in platform.lower():
                            matched_techniques.append(tech)
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('x_mitre_platforms', 'contains', name)
            ]
            matched_techniques = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            matched_techniques = self.parse_stix_objects(matched_techniques, Technique)
        return matched_techniques
    
    def get_techniques_by_tactic(
        self,
        name: str,
        case: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves techniques STIX objects associated with a specific tactic across all ATT&CK matrices. 
        The search can be case-sensitive or case-insensitive.

        Args:
            name (str): The name of the tactic to search for within the technique's kill chain phases.
            case (bool, optional): Determines if the search should be case sensitive. Default is True.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if not case:
            all_techniques = self.get_techniques()
            matched_techniques = []
            for tech in all_techniques:
                if 'kill_chain_phases' in tech.keys():
                     if name.lower() in tech['kill_chain_phases'][0]['phase_name'].lower():
                        matched_techniques.append(tech)
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('kill_chain_phases.phase_name', '=', name)
            ]
            matched_techniques = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            matched_techniques = self.parse_stix_objects(matched_techniques, Technique)
        return matched_techniques

    def get_object_by_attack_id(self, object_type: str, attack_id: str, stix_format: bool = True) -> List:
        """
        Retrieves a specific STIX object identified by an ATT&CK ID across all ATT&CK matrices.

        Args:
            object_type (str): The type of STIX object to retrieve, such as 'attack-pattern', 'course-of-action', 'intrusion-set',
                            'malware', 'tool', or 'x-mitre-data-component'.
            attack_id (str): The ATT&CK ID (e.g., 'T1234') of the STIX object to retrieve.
            stix_format (bool, optional): If True, returns the STIX object in its original format. If False,
                                        returns the STIX object as a custom dictionary parsed according to the corresponding Pydantic model.
                                        Default is True.

        Returns:
            List: A list containing the matched STIX object, either in its raw STIX format or as a custom dictionary
                    following the structure defined by the relevant Pydantic model, depending on the 'stix_format' flag.
        """
        valid_objects = {'attack-pattern','course-of-action','intrusion-set','malware','tool','x-mitre-data-source', 'x-mitre-data-component', 'campaign'}
        if object_type not in valid_objects:
            raise ValueError(f"ERROR: Valid object must be one of {valid_objects}")
        else:
            filter_objects = [
                Filter('type', '=', object_type),
                Filter('external_references.external_id', '=', attack_id)
            ]
            all_stix_objects = self.COMPOSITE_DS.query(filter_objects)
            if not stix_format:
                # Get the Pydantic model class for the current STIX object type
                pydantic_model = self.pydantic_model_mapping.get(object_type)
                # Parse the STIX objects using the appropriate Pydantic model
                if pydantic_model:
                    all_stix_objects = self.parse_stix_objects(all_stix_objects, pydantic_model)
            return all_stix_objects

    def get_campaign_by_alias(
        self,
        alias: str,
        case: bool = True,
        stix_format: bool = True
    ) -> List[Union[Campaign_v21, Dict[str, Any]]]:
        """
        Retrieves campaign STIX objects associated with a specific alias across all ATT&CK matrices. 
        The search can be case-sensitive or case-insensitive.

        Args:
            alias (str): The alias of the campaign to search for.
            case (bool, optional): Determines if the search should be case sensitive. Default is True.
            stix_format (bool, optional): If True, returns campaign objects in their original STIX format. If False,
                                        returns campaigns as custom dictionaries parsed according to the Campaign Pydantic model.
                                        Default is True.

        Returns:
            List[Union[Campaign_v21, Dict[str, Any]]]: A list of campaign objects, either as STIX objects (Campaign_v21) 
                or as custom dictionaries following the structure defined by the Campaign Pydantic model, depending
                on the 'stix_format' flag.
        """
        if not case:
            all_campaigns = self.get_campaigns()
            all_campaigns_list = list()
            for campaign in all_campaigns:
                if "aliases" in campaign.keys():
                    for campaign_alias in campaign['aliases']:
                        if alias.lower() in campaign_alias.lower():
                            all_campaigns_list.append(campaign)
        else:
            filter_objects = [
                Filter('type', '=', 'campaign'),
                Filter('aliases', 'contains', alias)
            ]
            all_campaigns_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_campaigns_list = self.parse_stix_objects(all_campaigns_list, Campaign)
        return all_campaigns_list

    def get_group_by_alias(
        self,
        alias: str,
        case: bool = True,
        stix_format: bool = True
    ) -> List[Union[IntrusionSet_v21, Dict[str, Any]]]:
        """
        Retrieves group STIX objects associated with a specific alias across all ATT&CK matrices. 
        The search can be case-sensitive or case-insensitive.

        Args:
            alias (str): The alias of the group to search for.
            case (bool, optional): Determines if the search should be case sensitive. Default is True.
            stix_format (bool, optional): If True, returns group objects in their original STIX format. If False,
                                        returns groups as custom dictionaries parsed according to the Group Pydantic model.
                                        Default is True.

        Returns:
            List[Union[IntrusionSet_v21, Dict[str, Any]]]: A list of group objects, either as STIX objects (IntrusionSet_v21)
                or as custom dictionaries following the structure defined by the Group Pydantic model, depending
                on the 'stix_format' flag.
        """
        if not case:
            all_groups = self.get_groups()
            all_groups_list = list()
            for group in all_groups:
                if "aliases" in group.keys():
                    for group_alias in group['aliases']:
                        if alias.lower() in group_alias.lower():
                            all_groups_list.append(group)
        else:
            filter_objects = [
                Filter('type', '=', 'intrusion-set'),
                Filter('aliases', '=', alias)
            ]
            all_groups_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_groups_list = self.parse_stix_objects(all_groups_list, Group)
        return all_groups_list

    def get_campaigns_since_time(self, timestamp: str, stix_format: bool = True) -> List[Union[Campaign_v21, Dict[str, Any]]]:
        """
        Retrieves campaign STIX objects created or modified since a specific timestamp across all ATT&CK matrices.

        Args:
            timestamp (str): The timestamp to filter campaigns that have been created or modified after this time.
            stix_format (bool, optional): If True, returns campaign objects in their original STIX format. If False,
                                        returns campaigns as custom dictionaries parsed according to the Campaign
                                        Pydantic model. Default is True.

        Returns:
            List[Union[Campaign_v21, Dict[str, Any]]]: A list of campaign objects, either as STIX objects (Campaign_v21) 
                or as custom dictionaries following the structure defined by the Campaign Pydantic model, depending
                on the 'stix_format' flag.
        """
        filter_objects = [
            Filter('type', '=', 'campaign'),
            Filter('created', '>', timestamp)
        ]
        all_campaigns_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_campaigns_list = self.parse_stix_objects(all_campaigns_list, Campaign)
        return all_campaigns_list

    def get_techniques_since_time(self, timestamp: str, stix_format: bool = True) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves technique STIX objects created or modified since a specific timestamp across all ATT&CK matrices.

        Args:
            timestamp (str): The timestamp to filter techniques that have been created or modified after this time.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('created', '>', timestamp)
        ]
        matched_techniques = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            matched_techniques = self.parse_stix_objects(matched_techniques, Technique)
        return matched_techniques

    def get_relationships_by_object(
        self, 
        stix_object: Any, 
        relationship_type: str = None, 
        source_only: bool = False, 
        target_only: bool = False, 
        skip_revoked_deprecated: bool = True, 
        stix_format: bool = True
    ) -> List[Union[Relationship_v21, Dict[str, Any]]]:
        """
        Retrieves relationship STIX objects associated with a specified STIX object across all ATT&CK matrices.

        Args:
            stix_object (any): STIX Object to extract relationships from.
            relationship_type (str, optional): Type of relationship (e.g., 'uses', 'mitigates') to filter the relationships. Default is None.
            source_only (bool, optional): If True, only retrieves relationships where the specified object is the source. Default is False.
            target_only (bool, optional): If True, only retrieves relationships where the specified object is the target. Default is False.
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated relationship objects. Default is True.
            stix_format (bool, optional): If True, returns relationship objects in their original STIX format. If False,
                                        returns relationships as custom dictionaries parsed according to the Relationship Pydantic model.
                                        Default is True.

        Returns:
            List[Union[Relationship_v21, Dict[str, Any]]]: A list of relationship objects, either as STIX objects (Relationship_v21)
                or as custom dictionaries following the structure defined by the Relationship Pydantic model, depending
                on the 'stix_format' flag.
        """
        if source_only and target_only:
            raise ValueError("ERROR: You can only set source_only or target_only but not both")
        else:
            if not relationship_type:
                type_lookup = {
                    "course-of-action" : "mitigates",
                    "x-mitre-data-component" : "detects",
                    "attack-pattern" : "subtechnique-of",
                    "malware" : "uses",
                    "tool" : "uses",
                    "intrusion-set" : "uses"
                }
                relationship_type = type_lookup[stix_object['type']]
            if source_only:
                relationships = self.COMPOSITE_DS.relationships(stix_object, relationship_type, source_only=True)
            elif target_only:
                relationships = self.COMPOSITE_DS.relationships(stix_object, relationship_type, target_only=True)
            else:
                relationships = self.COMPOSITE_DS.relationships(stix_object, relationship_type)

        if skip_revoked_deprecated:
            relationships = self.remove_revoked_deprecated(relationships)
        
        if not stix_format:
            relationships = self.parse_stix_objects(relationships, Relationship)
        return relationships
    
    def get_techniques_by_relationship(
        self, 
        stix_object: Any = None, 
        relationship_type: str = None, 
        skip_revoked_deprecated: bool = True, 
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves techniques related to a specified STIX object by a specific relationship type across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): STIX object whose relationships will be used to find related techniques.
            relationship_type (str, optional): Type of relationship (e.g., 'uses', 'subtechnique-of') to filter the techniques.
            skip_revoked_deprecated (bool, optional): If True, excludes revoked and deprecated techniques from the results. Default is True.
            stix_format (bool, optional): If True, returns techniques in their original STIX format. If False, 
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        if stix_object and relationship_type:
            relationships = self.get_relationships_by_object(stix_object, relationship_type, skip_revoked_deprecated=skip_revoked_deprecated, source_only=True)
        elif stix_object and not relationship_type:
            relationships = self.get_relationships_by_object(stix_object, skip_revoked_deprecated=skip_revoked_deprecated, source_only=True)
        elif relationship_type and not stix_object:
            relationship_types = ['uses', 'mitigates', 'subtechnique-of', 'detects', 'revoked-by']
            if relationship_type not in relationship_types:
                raise ValueError(f"ERROR: Valid relationship types must be one of {relationship_types}")
            else:
                relationships = self.get_relationships(relationship_type=relationship_type, skip_revoked_deprecated=skip_revoked_deprecated)
        else:
            relationships = self.get_relationships(skip_revoked_deprecated=skip_revoked_deprecated)

        # Define Filter and query all matrices
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', list(set([r.target_ref for r in relationships])))
        ]
        all_objects = self.COMPOSITE_DS.query(filter_objects)

        # Remove revoked or deprecated techniques
        if skip_revoked_deprecated:
            all_objects = self.remove_revoked_deprecated(all_objects)

        if not stix_format:
            all_objects = self.parse_stix_objects(all_objects, Technique)
        
        return all_objects 
    
    def get_techniques_used_by_group(
        self,
        stix_object: Any = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves techniques used by a specified group STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): group STIX object used to find related techniques.
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects, either as STIX objects (AttackPattern_v21)
                or as custom dictionaries following the structure defined by the Technique Pydantic model, depending
                on the 'stix_format' flag.
        """
        return self.get_techniques_by_relationship(stix_object, None, skip_revoked_deprecated, stix_format)
    
    def get_techniques_used_by_all_groups(self, stix_format: bool = True) -> List:
        """
        Retrieves techniques used by all groups object across all ATT&CK matrices.

        Args:
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List: A list of technique objects used by a all groups, either as STIX objects or as custom dictionaries following the
                    structure defined by the GroupTechnique Pydantic model, depending on the 'stix_format' flag.
        """
        groups = self.get_groups()
        techniques = self.get_techniques()
        group_relationships = list()
        group_techniques_ref = list()
        groups_use_techniques = list()
        filters = [
            Filter("type", "=", "relationship"),
            Filter('relationship_type','=','uses')
        ]
        relationships = self.COMPOSITE_DS.query(filters)
        
        for rel in relationships:
            if get_type_from_id(rel.source_ref) == 'intrusion-set'\
            and get_type_from_id(rel.target_ref) == 'attack-pattern':
                group_relationships.append(rel)
        
        for g in groups:
            for rel in group_relationships:
                if g['id'] == rel['source_ref']:
                    gs = json.loads(g.serialize())
                    gs['technique_ref'] = rel['target_ref']
                    gs['relationship_description'] = rel['description']
                    gs['relationship_id'] = rel['id']
                    group_techniques_ref.append(gs)
        
        for gt in group_techniques_ref:
            for t in techniques:
                if gt['technique_ref'] == t['id']:
                    if 'revoked' in t.keys():
                        gt['revoked'] = t['revoked']
                    tactic_list = list()
                    if 'kill_chain_phases' in t.keys():
                        tactic_list = t['kill_chain_phases']
                    gt['technique'] = t['name']
                    if 'description' in t.keys():
                        gt['technique_description'] = t['description']
                    gt['tactic'] = tactic_list
                    gt['technique_id'] = t['external_references'][0]['external_id']
                    gt['technique_matrix'] =  t['x_mitre_domains']
                    if 'x_mitre_platforms' in t.keys():
                        gt['platform'] = t['x_mitre_platforms']
                    if 'x_mitre_data_sources' in t.keys():
                        gt['data_sources'] = t['x_mitre_data_sources']
                    if 'x_mitre_permissions_required' in t.keys():
                        gt['permissions_required'] = t['x_mitre_permissions_required']
                    if 'x_mitre_effective_permissions' in t.keys():
                        gt['effective_permissions'] = t['x_mitre_effective_permissions']
                    groups_use_techniques.append(gt)
        if not stix_format:
            groups_use_techniques = self.parse_stix_objects(groups_use_techniques, GroupTechnique)
        return groups_use_techniques

    def get_software_used_by_group(
        self,
        stix_object: Any = None,
        stix_format: bool = True,
        batch_size=10
    ) -> List[Union[Malware_v21, Tool_v21, Dict[str, Any]]]:
        """
        Retrieves software (Malware and Tools) used by a specified group STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): group STIX object used to find related software.
            stix_format (bool, optional): If True, returns Software (Malware or Tool) objects in their original STIX format.
                                        If False, returns Malware or Tools as custom dictionaries parsed according to the Software
                                        Pydantic model. Default is True.
            batch_size (int): The batch size to use when querying the TAXII datastore. Use a lower batch size if the
                              URI becomes too long and you get HTTP 414 errors.

        Returns:
            List[Union[Malware_v21, Tool_v21, Dict[str, Any]]]: A list of software objects used by a specific group, either as 
                STIX objects (Malware_v21 or Tool_v21) or as custom dictionaries following the structure defined
                by the Software Pydantic model, depending on the 'stix_format' flag.
        """
        relationships = self.get_relationships_by_object(stix_object, source_only=True)
        software_relationships = list()
        for relation in relationships:
            if get_type_from_id(relation.target_ref) in ['malware', 'tool']:
                software_relationships.append(relation)
        if len(software_relationships) == 0:
            return software_relationships
        
        all_software = []

        for software_relation_batch in [software_relationships[i:i+batch_size] for i in range(0, len(software_relationships), batch_size)]:
            filter_objects = [
                Filter('type', 'in', ['malware', 'tool']),
                Filter('id', '=', [r.target_ref for r in software_relation_batch])
            ]
            
            search_results = self.COMPOSITE_DS.query(filter_objects)
            all_software.extend(search_results)

        if not stix_format:
            all_software = self.parse_stix_objects(all_software, Software)
        return all_software

    def get_techniques_used_by_software(
        self,
        stix_object: Any = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves techniques used by a specified software STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): software STIX object used to find related techniques.
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects used by a specific software
                (Malware or Tool), either as STIX objects (AttackPattern_v21) or as custom dictionaries following
                the structure defined by the Technique Pydantic model, depending on the 'stix_format' flag.
        """
        return self.get_techniques_by_relationship(stix_object, None, skip_revoked_deprecated, stix_format )
    
    def get_techniques_used_by_group_software(
        self,
        stix_object: Any = None,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves techniques used by a specific group software STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): group software STIX object used to find related techniques.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects used by a specific group software,
                either as STIX objects (AttackPattern_v21) or as custom dictionaries following the structure defined
                by the Technique Pydantic model, depending on the 'stix_format' flag.
        """
        # Get all relationships available for group
        relationships = self.get_relationships_by_object(stix_object, source_only=True)
        software_relationships = list()
        # Get all software relationships from group
        for relation in relationships:
            if get_type_from_id(relation.target_ref) in ['malware', 'tool']:
                software_relationships.append(relation)
        if len(software_relationships) == 0:
            return software_relationships
        # Get all used by the software that is used by group
        filter_objects = [
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.target_ref for r in software_relationships])
        ]
        software_uses = self.COMPOSITE_DS.query(filter_objects)
        # Get all techniques used by the software that is used by group
        filter_techniques = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [s.target_ref for s in software_uses])
        ]
        matched_techniques = self.COMPOSITE_DS.query(filter_techniques)
        if not stix_format:
            matched_techniques = self.parse_stix_objects(matched_techniques, Technique)
        return matched_techniques
    
    def get_techniques_mitigated_by_mitigations(
        self,
        stix_object: Any = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves all techniques mitigated by all or one mitigations STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): mitigation STIX object used to find related techniques.
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique Pydantic model.
                                        Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique objects mitigated by mitigations,
                either as STIX objects (AttackPattern_v21) or as custom dictionaries following the structure defined
                by the Technique Pydantic model, depending on the 'stix_format' flag.
        """
        if stix_object:
            all_techniques = self.get_techniques_by_relationship(stix_object, 'mitigates', skip_revoked_deprecated, stix_format)
        else:
            all_techniques = self.get_techniques_by_relationship(relationship_type="mitigates", skip_revoked_deprecated=skip_revoked_deprecated, stix_format=stix_format)

        return all_techniques
    
    def get_techniques_detected_by_data_components(
        self,
        stix_object: Any = None,
        skip_revoked_deprecated: bool = True,
        stix_format: bool = True
    ) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Retrieves all techniques detected by all or one data component STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): data component STIX object used to find related techniques.
            skip_revoked_deprecated (bool, optional): If True, filters out revoked and deprecated technique objects.
                                                    Default is True.
            stix_format (bool, optional): If True, returns technique objects in their original STIX format. If False,
                                        returns techniques as custom dictionaries parsed according to the Technique
                                        Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique detected by data components
                either as STIX objects (AttackPattern_v21) or as custom dictionaries following the structure defined
                by the Technique Pydantic model, depending on the 'stix_format' flag.
        """
        if stix_object:
            all_techniques = self.get_techniques_by_relationship(stix_object, 'detects', skip_revoked_deprecated, stix_format)
        else:
            all_techniques = self.get_techniques_by_relationship(relationship_type="detects", skip_revoked_deprecated=skip_revoked_deprecated, stix_format=stix_format)

        return all_techniques

    def get_data_components_by_technique(self, stix_object: Any = None, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Retrieves data components by a specified technique STIX object across all ATT&CK matrices.

        Args:
            stix_object (Any, optional): technique STIX object used to find related data components.
            stix_format (bool, optional): If True, returns  data component objects in their original STIX format. If False,
                                        returns data components as custom dictionaries parsed according to the DataComponent
                                        Pydantic model. Default is True.

        Returns:
            List[Dict[str, Any]]: A list of data component objects, either as STIX objects or as custom dictionaries following the
                structure defined by the DataComponent Pydantic model, depending on the 'stix_format' flag.
        """
        relationships = self.get_relationships_by_object(stix_object, relationship_type='detects', target_only=True)
        filter_objects = [
            Filter('type', '=', ['x-mitre-data-component']),
            Filter('id', 'in', [r.source_ref for r in relationships])
        ]
        all_data_components = self.COMPOSITE_DS.query(filter_objects)

        if not stix_format:
            all_data_components = self.parse_stix_objects(all_data_components, DataComponent)
        return all_data_components

    def get_data_sources_metadata(self) -> List[str]:
        """ 
        Extracts data sources metadata from all technique STIX objects accross all ATT&CK matrices.
        This function uses the x_mitre_data_sources field from attack-pattern objects.
        This function does NOT retrieve data sources as objects. Data sources as objects are now retrieved by the get_data_sources() function.

        Returns:
            List[str]: A list of data sources as strings.
        """
        techniques = self.get_techniques()
        data_sources = []
        for t in techniques:
            if 'x_mitre_data_sources' in t.keys():
                data_sources += [d for d in t['x_mitre_data_sources'] if d not in data_sources]
        return data_sources

    def get_techniques_by_data_sources(self, *data_sources, stix_format=True) -> List[Union[AttackPattern_v21, Dict[str, Any]]]:
        """
        Extracts technique STIX objects by specific data sources across all ATT&CK matrices.

        Args:
            *data_sources (str): An arbitrary number of strings, each representing the name of a data source. 
                                Techniques related to any of these data sources will be extracted.
            stix_format (bool, optional): If True, returns results in original STIX format. If False,
                                returns techniques as custom dictionaries parsed according to the Technique
                                Pydantic model. Default is True.

        Returns:
            List[Union[AttackPattern_v21, Dict[str, Any]]]: A list of technique related to specific data sources
                either as STIX objects (AttackPattern_v21) or as custom dictionaries following the structure defined
                by the Technique Pydantic model, depending on the 'stix_format' flag.
        """
        techniques_results = []
        techniques = self.get_techniques()
        for d in data_sources:
            for t in techniques:
                if 'x_mitre_data_sources' in t.keys() and any(d.lower() in x.lower() for x in t['x_mitre_data_sources']):
                    if t not in techniques_results:
                        techniques_results.append(t)
        if not stix_format:
            techniques_results = self.parse_stix_objects(techniques_results, Technique)
        return techniques_results

    def export_groups_navigator_layers(self):
        """ Export group STIX objects metadata in MITRE Navigator Layers format """
        techniques_used = self.get_techniques_used_by_all_groups()
        groups = self.get_groups()
        groups_list = []
        for g in groups:
            group_dict = dict()
            group_dict[g['name']] = []
            groups_list.append(group_dict)      
        for group in groups_list:
            for group_name,techniques_list in group.items():
                for gut in techniques_used:
                    if group_name == gut['name']:
                        technique_dict = dict()
                        technique_dict['techniqueId'] = gut['technique_id']
                        technique_dict['techniqueName'] = gut['technique']
                        technique_dict['comment'] = gut['relationship_description']
                        technique_dict['tactic'] = gut['tactic']
                        technique_dict['group_id'] = gut['external_references'][0]['external_id']
                        if 'data_sources' in gut.keys():
                            technique_dict['dataSources'] = gut['data_sources']
                        techniques_list.append(technique_dict)
        for group in groups_list:
            for k,v in group.items():
                if v:
                    actor_layer = {
                        "description": ("Enterprise techniques used by {0}, ATT&CK group {1} v1.0".format(k,v[0]['group_id'])),
                        "name": ("{0} ({1})".format(k,v[0]['group_id'])),
                        "domain": "enterprise-attack",
                        "versions": {
                            "attack": "16",
                            "navigator": "5.1.0",
                            "layer": "4.5"
                        },
                        "techniques": [
                            {
                                "score": 1,
                                "techniqueID" : technique['techniqueId'],
                                "techniqueName" : technique['techniqueName'],
                                "comment": technique['comment']
                            } for technique in v
                        ],
                        "gradient": {
                            "colors": [
                                "#ffffff",
                                "#ff6666"
                            ],
                            "minValue": 0,
                            "maxValue": 1
                        },
                        "legendItems": [
                            {
                                "label": ("used by {}".format(k)),
                                "color": "#ff6666"
                            }
                        ]
                    }
                    with open(('{0}_{1}.json'.format(k,v[0]['group_id'])), 'w') as f:
                        f.write(json.dumps(actor_layer))
    
    def  get_data_components_by_data_source(self, stix_object: Any, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Extracts data component STIX objects referenced by a specific data source STIX object.

        Args:
            stix_object (Any): The STIX object representing the data source from which
                                        data component STIX objects are to be retrieved. It must
                                        include an 'id' key that represents the STIX identifier of the data source.
            stix_format (bool, optional): If True, returns results in the original STIX format. If False,
                                        returns data components as custom dictionaries parsed according
                                        to the DataComponent Pydantic model. Default is True.

        Returns:
            List[Dict[str, Any]]: A list of data component objects, either as STIX objects or as custom dictionaries
                following the structure defined by the DataComponent Pydantic model, depending on the 'stix_format' flag.
        """
        filter_objects = [
            Filter('type', '=', 'x-mitre-data-component'),
            Filter('x_mitre_data_source_ref', '=', stix_object['id'])
        ]
        data_components = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            data_components = self.parse_stix_objects(data_components, DataComponent)
        return data_components

    def get_data_source_by_data_component(self, stix_object: Any, stix_format: bool = True) -> List[Dict[str, Any]]:
        """
        Extracts data source STIX objects referenced by a specific data component STIX object.

        Args:
            stix_object (Any): The STIX object representing the data component from which
                                        data source STIX objects are to be retrieved. It must
                                        include an 'id' key that represents the STIX identifier of the data component.
            stix_format (bool, optional): If True, returns results in the original STIX format. If False,
                                        returns data sources as custom dictionaries parsed according
                                        to the DataSource Pydantic model. Default is True.

        Returns:
            List: A list of data source objects related to data components, either as dictionaries following the original STIX structure
                or defined by the DataSource Pydantic model, depending on the 'stix_format' flag.
        """

        filter_objects = [
            Filter('type', '=', 'x-mitre-data-source'),
            Filter('id', '=', stix_object['x_mitre_data_source_ref'])
        ]

        data_source = self.COMPOSITE_DS.query(filter_objects)

        if not stix_format:
            data_source = self.parse_stix_objects(data_source, DataSource)

        return data_source

    def enrich_techniques_data_sources(self, stix_objects: List) -> List:
        """
        Adds data sources and their respective data components context to a list of STIX Technique objects.
        This function enhances each technique with detailed data source information, making the contextual
        details of each technique more comprehensive and actionable.

        Args:
            stix_objects (List): A list of STIX objects representing techniques, where
                                    each technique is expected to be a dictionary containing at least the STIX ID.

        Returns:
            List: A list of enriched STIX objects representing techniques, each now including
                    additional context about data sources and data components associated with the technique.
        """
        # Get 'detects' relationships
        relationships = self.get_relationships(relationship_type='detects')

        # Get all data component objects
        data_components = self.get_data_components()

        # Get all data source objects without data components objects
        data_sources = self.get_data_sources()

        # Create Data Sources and Data Components lookup tables
        ds_lookup = {ds['id']:ds for ds in data_sources}
        dc_lookup = {dc['id']:dc for dc in data_components}

        # https://stix2.readthedocs.io/en/latest/guide/versioning.html
        for i in range(len(stix_objects)):
            technique_ds = dict()
            for rl in relationships:
                if stix_objects[i]['id'] == rl['target_ref']:
                    dc = dc_lookup[rl['source_ref']]
                    dc_ds_ref = dc['x_mitre_data_source_ref']
                    if dc_ds_ref not in technique_ds.keys():
                        technique_ds[dc_ds_ref] = ds_lookup[dc_ds_ref].copy()
                        technique_ds[dc_ds_ref]['data_components'] = list()
                    if dc not in technique_ds[dc_ds_ref]['data_components']:
                        technique_ds[dc_ds_ref]['data_components'].append(dc)
            if technique_ds:
                new_data_sources = [ v for v in technique_ds.values()]
                stix_objects[i] = stix_objects[i].new_version(x_mitre_data_sources = new_data_sources)
        return stix_objects
