"""Domain-specific convenience methods."""

from __future__ import annotations

from typing import Any, Dict, List, Union

from stix2 import Filter
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21,
    Campaign as Campaign_v21,
    CourseOfAction as CourseOfAction_v21,
    IntrusionSet as IntrusionSet_v21,
    Malware as Malware_v21,
    Tool as Tool_v21,
)
from stix2.v21.sro import Relationship as Relationship_v21

from .models import (
    Campaign,
    DataComponent,
    DataSource,
    Group,
    Mitigation,
    Relationship,
    Software,
    Tactic,
    Technique,
)

__all__ = [
    'get_enterprise',
    'get_enterprise_campaigns',
    'get_enterprise_techniques',
    'get_enterprise_data_components',
    'get_enterprise_mitigations',
    'get_enterprise_groups',
    'get_enterprise_malware',
    'get_enterprise_tools',
    'get_enterprise_relationships',
    'get_enterprise_tactics',
    'get_enterprise_data_sources',
    'get_mobile',
    'get_mobile_campaigns',
    'get_mobile_techniques',
    'get_mobile_data_components',
    'get_mobile_mitigations',
    'get_mobile_groups',
    'get_mobile_malware',
    'get_mobile_tools',
    'get_mobile_relationships',
    'get_mobile_tactics',
    'get_mobile_data_sources',
    'get_ics',
    'get_ics_campaigns',
    'get_ics_techniques',
    'get_ics_data_components',
    'get_ics_mitigations',
    'get_ics_groups',
    'get_ics_malware',
    'get_ics_tools',
    'get_ics_relationships',
    'get_ics_tactics',
    'get_ics_data_sources',
]


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
