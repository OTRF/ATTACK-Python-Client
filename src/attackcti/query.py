"""High-level query helpers across domains."""

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
    'get_attack',
    'get_campaigns',
    'get_techniques',
    'get_groups',
    'get_mitigations',
    'get_data_components',
    'get_software',
    'get_relationships',
    'get_tactics',
    'get_data_sources',
    'get_technique_by_name',
    'get_techniques_by_content',
    'get_techniques_by_platform',
    'get_techniques_by_tactic',
    'get_object_by_attack_id',
    'get_campaign_by_alias',
    'get_group_by_alias',
    'get_campaigns_since_time',
    'get_techniques_since_time',
]


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
