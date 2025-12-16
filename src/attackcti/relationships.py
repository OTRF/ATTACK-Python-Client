"""Relationship and enrichment helpers."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Union

from stix2 import Filter
from stix2.utils import get_type_from_id
from stix2.v21.sdo import (
    AttackPattern as AttackPattern_v21,
    Malware as Malware_v21,
    Tool as Tool_v21,
)
from stix2.v21.sro import Relationship as Relationship_v21

from .models import (
    DataComponent,
    DataSource,
    GroupTechnique,
    Relationship,
    Software,
    Technique,
)

__all__ = [
    'get_relationships_by_object',
    'get_techniques_by_relationship',
    'get_techniques_used_by_group',
    'get_techniques_used_by_all_groups',
    'get_software_used_by_group',
    'get_techniques_used_by_software',
    'get_techniques_used_by_group_software',
    'get_techniques_mitigated_by_mitigations',
    'get_techniques_detected_by_data_components',
    'get_data_components_by_technique',
    'get_data_sources_metadata',
    'get_techniques_by_data_sources',
    'export_groups_navigator_layers',
    'get_data_components_by_data_source',
    'get_data_source_by_data_component',
    'enrich_techniques_data_sources',
]


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
