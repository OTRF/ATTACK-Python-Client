#!/usr/bin/env python

# ATT&CK Client Main Script
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: BSD 3-Clause
# Reference:
# https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via
# https://github.com/mitre/cti/blob/master/USAGE.md
# https://github.com/oasis-open/cti-python-stix2/issues/183
# https://stackoverflow.com/a/4406521

from stix2 import TAXIICollectionSource, Filter, CompositeDataSource, FileSystemSource
from stix2.datastore.filters import apply_common_filters
from stix2.utils import get_type_from_id
#from stix2.v20.sdo import *
from taxii2client.v20 import Collection
import json
import os
import warnings

# os.environ['http_proxy'] = "http://xxxxxxx"
# os.environ['https_proxy'] = "https://xxxxxxx"

ATTACK_STIX_COLLECTIONS = "https://cti-taxii.mitre.org/stix/collections/"
ENTERPRISE_ATTACK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
PRE_ATTACK = "062767bd-02d2-4b72-84ba-56caef0f8658"
MOBILE_ATTACK = "2f669986-b40b-4423-b720-4396ca6a462b"
ICS_ATTACK = "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"

ENTERPRISE_ATTACK_LOCAL_DIR = "enterprise-attack"
PRE_ATTACK_LOCAL_DIR = "pre-attack"
MOBILE_ATTACK_LOCAL_DIR = "mobile-attack"
ICS_ATTACK_LOCAL_DIR = "ics-attack"

class attack_client(object):
    """A Python Module for ATT&CK"""
    TC_ENTERPRISE_SOURCE = None
    TC_PRE_SOURCE = None
    TC_MOBILE_SOURCE = None
    TC_ICS_SOURCE = None
    COMPOSITE_DS = None

    def __init__(self, local_path=None, include_pre_attack=False):
        if local_path is not None and os.path.isdir(os.path.join(local_path, ENTERPRISE_ATTACK_LOCAL_DIR)) \
                                  and os.path.isdir(os.path.join(local_path, PRE_ATTACK_LOCAL_DIR)) \
                                  and os.path.isdir(os.path.join(local_path, MOBILE_ATTACK_LOCAL_DIR)) \
                                  and os.path.isdir(os.path.join(local_path, ICS_ATTACK_LOCAL_DIR)):
            self.TC_ENTERPRISE_SOURCE = FileSystemSource(os.path.join(local_path, ENTERPRISE_ATTACK_LOCAL_DIR))
            self.TC_PRE_SOURCE = FileSystemSource(os.path.join(local_path, PRE_ATTACK_LOCAL_DIR))
            self.TC_MOBILE_SOURCE = FileSystemSource(os.path.join(local_path, MOBILE_ATTACK_LOCAL_DIR))
            self.TC_ICS_SOURCE = FileSystemSource(os.path.join(local_path, ICS_ATTACK_LOCAL_DIR))
        else:
            ENTERPRISE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + ENTERPRISE_ATTACK + "/")
            PRE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + PRE_ATTACK + "/")
            MOBILE_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + MOBILE_ATTACK + "/")
            ICS_COLLECTION = Collection(ATTACK_STIX_COLLECTIONS + ICS_ATTACK + "/")

            self.TC_ENTERPRISE_SOURCE = TAXIICollectionSource(ENTERPRISE_COLLECTION)
            self.TC_PRE_SOURCE = TAXIICollectionSource(PRE_COLLECTION)
            self.TC_MOBILE_SOURCE = TAXIICollectionSource(MOBILE_COLLECTION)
            self.TC_ICS_SOURCE = TAXIICollectionSource(ICS_COLLECTION)

        self.COMPOSITE_DS = CompositeDataSource()
        self.COMPOSITE_DS.add_data_sources([self.TC_ENTERPRISE_SOURCE, self.TC_MOBILE_SOURCE, self.TC_ICS_SOURCE])

        if include_pre_attack:
            self.COMPOSITE_DS.add_data_sources([self.TC_PRE_SOURCE])

    def translate_stix_objects(self, stix_objects):
        technique_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "object_marking_refs": "object_marking_refs",
            "name": "technique",
            "description": "technique_description",
            "kill_chain_phases": "tactic",
            "x_mitre_detection": "technique_detection",
            "x_mitre_platforms": "platform",
            "x_mitre_data_sources": "data_sources",
            "x_mitre_defense_bypassed": "defense_bypassed",
            "x_mitre_permissions_required": "permissions_required",
            "x_mitre_effective_permissions": "effective_permissions",
            "x_mitre_system_requirements": "system_requirements",
            "x_mitre_network_requirements": "network_requirements",
            "x_mitre_remote_support": "remote_support",
            "x_mitre_contributors": "contributors",
            "x_mitre_detectable_by_common_defenses": "detectable_by_common_defenses",
            "x_mitre_detectable_by_common_defenses_explanation": "detectable_explanation",
            "x_mitre_difficulty_for_adversary": "difficulty_for_adversary",
            "x_mitre_difficulty_for_adversary_explanation": "difficulty_explanation",
            "x_mitre_tactic_type": "tactic_type",
            "x_mitre_impact_type": "impact_type",
            "x_mitre_is_subtechnique": "is_subtechnique",
            "external_references": "external_references"
        }
        mitigation_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "name": "mitigation",
            "description": "mitigation_description",
            "external_references": "external_references",
            "x_mitre_old_attack_id": "old_mitigation_id"
        }
        group_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "name": "group",
            "description": "group_description",
            "aliases": "group_aliases",
            "external_references": "external_references",
            "x_mitre_contributors": "contributors"
        }
        software_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "name": "software",
            "description": "software_description",
            "labels": "software_labels",
            "x_mitre_aliases": "software_aliases",
            "x_mitre_platforms": "software_platform",
            "external_references": "external_references",
            "x_mitre_contributors": "contributors",
            "x_mitre_old_attack_id": "old_software_id"
        }
        data_component_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "name": "data_component",
            "description": "data_component_description",
            "labels": "data_component_labels",
            "x_mitre_data_source_ref": "data_source",
        }
        relationship_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "relationship_type": "relationship",
            "description": "relationship_description",
            "source_ref": "source_object",
            "target_ref": "target_object"
        }
        tactic_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "object_marking_refs": "object_marking_refs",
            "name": "tactic",
            "description": "tactic_description",
            "x_mitre_shortname": "tactic_shortname",
            "external_references": "external_references"

        }
        matrix_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",
            "object_marking_refs": "object_marking_refs",
            "name": "matrix",
            "description": "matrix_description",
            "tactic_refs": "tactic_references",
            "external_references": "external_references"
        }
        identity_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "definition_type": "marking_definition_type",
            "definition":"marking_definition"
        }
        marking_stix_mapping = {
            "type": "type",
            "id": "id",
            "created": "created",
            "modified": "modified",
            "object_marking_refs": "object_marking_refs",
            "name": "identity",
            "identity_class": "identity_class"
        }
        data_source_stix_mapping = {
            "type": "type",
            "id": "id",
            "created": "created",
            "modified": "modified",
            "name": "data_source",
            "description": "description",
            "created_by_ref": "created_by_ref",
            "external_references": "external_references",
            "x_mitre_platforms": "software_platform",
            "x_mitre_collection_layers": "collection_layers",
            "x_mitre_contributors": "contributors"
        }
        campaign_stix_mapping = {
            "type": "type",
            "id": "id",
            "created_by_ref": "created_by_ref",
            "created": "created",
            "modified": "modified",      
            "name": "name",
            "description": "campaign_description",
            "aliases": "campaign_aliases",
            "object_marking_refs": "object_marking_refs",
            "external_references": "external_references",
            "x_mitre_first_seen_citation": "first_seen_citation",
            "x_mitre_last_seen_citation": "last_seen_citation"
        }

        # ******** Helper Functions ********
        def handle_list(list_object, object_type):
            if object_type == "external_references":
                obj_dict['url'] = list_object[0]['url']
                obj_dict['matrix'] = list_object[0]['source_name']
                if obj_dict['type'] == 'attack-pattern':
                    for ref in list_object:
                        if ref['source_name'] == 'capec':
                            obj_dict['capec_id'] = ref['external_id']
                            obj_dict['capec_url'] = ref['url']
                    obj_dict['technique_id'] = list_object[0]['external_id']
                elif obj_dict['type'] == 'course-of-action':
                    obj_dict['mitigation_id'] = list_object[0]['external_id']
                elif obj_dict['type'] == 'group':
                    obj_dict['group_id'] = list_object[0]['external_id']
                elif obj_dict['type'] == 'software':
                    obj_dict['software_id'] = list_object[0]['external_id']
                elif obj_dict['type'] == 'tactic':
                    obj_dict['tactic_id'] = list_object[0]['external_id']
                elif obj_dict['type'] == 'matrix':
                    obj_dict['matrix_id'] = list_object[0]['external_id']
                elif obj_dict['type'] == 'campaign':
                    obj_dict['campaign_id'] = list_object[0]['external_id']
            elif object_type == "kill_chain_phases":
                tactic_list = list()
                for phase in list_object:
                    tactic_list.append(phase['phase_name'])
                obj_dict['tactic'] = tactic_list

        stix_objects_list = list()
        for obj in stix_objects:
            if isinstance(obj, dict):
                obj_dict = obj
            else:
                obj_dict = json.loads(obj.serialize()) # From STIX to Python Dict 
            dict_keys =  list(obj_dict.keys())
            for key in dict_keys:
                if obj['type'] == "attack-pattern":
                    stix_mapping = technique_stix_mapping
                elif obj['type'] == "course-of-action":
                    stix_mapping = mitigation_stix_mapping
                elif obj['type'] == "intrusion-set":
                    stix_mapping = group_stix_mapping
                elif obj['type'] == "malware" or obj['type'] == "tool":
                    stix_mapping = software_stix_mapping
                elif obj['type'] == "x-mitre-data-component":
                    stix_mapping = data_component_stix_mapping
                elif obj['type'] == "relationship":
                    stix_mapping = relationship_stix_mapping
                elif obj['type'] == "x-mitre-tactic":
                    stix_mapping = tactic_stix_mapping
                elif obj['type'] == "x-mitre-matrix":
                    stix_mapping = matrix_stix_mapping
                elif obj['type'] == "identity":
                    stix_mapping = identity_stix_mapping
                elif obj['type'] == "marking-definition":
                    stix_mapping = marking_stix_mapping
                elif obj['type'] == "x-mitre-data-source":
                    stix_mapping = data_source_stix_mapping
                elif obj['type'] == "campaign":
                    stix_mapping = campaign_stix_mapping
                else:
                    return stix_objects_list

                if key in stix_mapping.keys():
                    if key == "external_references" or key == "kill_chain_phases":
                        handle_list(obj_dict[key], key)
                    else:
                        new_key = stix_mapping[key]
                        obj_dict[new_key] = obj_dict.pop(key)
            stix_objects_list.append(obj_dict)
        return stix_objects_list

    # https://github.com/mitre/cti/issues/127
    # https://github.com/mitre/cti/blob/master/USAGE.md#removing-revoked-and-deprecated-objects
    def remove_revoked_deprecated(self, stix_objects):
        """Remove any revoked or deprecated objects from queries made to the data source"""
        return list(
            filter(
                lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
                stix_objects
            )
        )
    
    # https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html
    def extract_revoked(self, stix_objects):
        """Extract revoked objects from STIX objects"""
        return list(
            apply_common_filters(
                stix_objects,
                [Filter('revoked','=',True)]
        ))
    
    # https://stix2.readthedocs.io/en/latest/api/datastore/stix2.datastore.filters.html
    def extract_deprecated(self, stix_objects):
        """Extract deprecated objects from STIX objects"""
        return list(
            apply_common_filters(
                stix_objects,
                [Filter('x_mitre_deprecated','=',True)]
        ))

    # ******** Enterprise ATT&CK Technology Domain  *******
    def get_enterprise(self, stix_format=True):
        """ Extracts all the available STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')

        Returns:
            List of STIX objects
        
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
            "campaign": self.get_enterprise_campaigns
        }
        enterprise_stix_objects = dict()
        for key in enterprise_filter_objects:
            enterprise_stix_objects[key] = self.TC_ENTERPRISE_SOURCE.query(enterprise_filter_objects[key]) if isinstance(enterprise_filter_objects[key], Filter) else enterprise_filter_objects[key]()
            if not stix_format:
                enterprise_stix_objects[key] = self.translate_stix_objects(enterprise_stix_objects[key])
        return enterprise_stix_objects

    def get_enterprise_campaigns(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available campaigns STIX objects in the Enterprise ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects. 
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        enterprise_campaigns = self.TC_ENTERPRISE_SOURCE.query([Filter("type", "=", "campaign")])

        if skip_revoked_deprecated:
            enterprise_campaigns = self.remove_revoked_deprecated(enterprise_campaigns)
        
        if not stix_format:
            enterprise_campaigns = self.translate_stix_objects(enterprise_campaigns)
        return enterprise_campaigns

    def get_enterprise_techniques(self, skip_revoked_deprecated=True, include_subtechniques=True, enrich_data_sources = False, stix_format=True):
        """ Extracts all the available techniques STIX objects in the Enterprise ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects. 
            include_subtechniques (bool): default True. Include techniques and sub-techniques STIX objects.
            enrich_data_sources (bool): default False. Adds data component and data source context to each technqiue.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
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
            enterprise_techniques = self.translate_stix_objects(enterprise_techniques)
        return enterprise_techniques

    def get_enterprise_data_components(self, stix_format=True):
        """ Extracts all the available data components STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        enterprise_data_components = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        if not stix_format:
            enterprise_data_components = self.translate_stix_objects(enterprise_data_components)
        return enterprise_data_components

    def get_enterprise_mitigations(self, stix_format=True):
        """ Extracts all the available mitigations STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_mitigations = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            enterprise_mitigations = self.translate_stix_objects(enterprise_mitigations)
        return enterprise_mitigations
    
    def get_enterprise_groups(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available groups STIX objects in the Enterprise ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_groups = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            enterprise_groups = self.remove_revoked_deprecated(enterprise_groups)
        
        if not stix_format:
            enterprise_groups = self.translate_stix_objects(enterprise_groups)
        return enterprise_groups
    
    def get_enterprise_malware(self, stix_format=True):
        """ Extracts all the available malware STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_malware = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            enterprise_malware = self.translate_stix_objects(enterprise_malware)
        return enterprise_malware
    
    def get_enterprise_tools(self, stix_format=True):
        """ Extracts all the available tools STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_tools = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            enterprise_tools = self.translate_stix_objects(enterprise_tools)
        return enterprise_tools
    
    def get_enterprise_relationships(self, stix_format=True):
        """ Extracts all the available relationships STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_relationships = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            enterprise_relationships = self.translate_stix_objects(enterprise_relationships)
        return enterprise_relationships
    
    def get_enterprise_tactics(self, stix_format=True):
        """ Extracts all the available tactics STIX objects in the Enterprise ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_tactics = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            enterprise_tactics = self.translate_stix_objects(enterprise_tactics)
        return enterprise_tactics
    
    def get_enterprise_data_sources(self, include_data_components=False, stix_format=True):
        """ Extracts all the available data source STIX objects availalbe in the Enterprise ATT&CK matrix. This function filters all STIX objects by the type x-mitre-data-source.

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        enterprise_data_sources = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-data-source"))
        if include_data_components:
            for ds in enterprise_data_sources:
                ds['data_components']= self.get_data_components_by_data_source(ds)
        if not stix_format:
            enterprise_data_sources = self.translate_stix_objects(enterprise_data_sources)
        return enterprise_data_sources

    # ******** Pre ATT&CK Domain [DEPRECATED] 11/23/2020 *******
    def get_pre(self, stix_format=True):
        """ Extracts all the available STIX objects in the Pre ATT&CK matrix [ DEPRECATED AS OF 11/23/2020 ]

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        warnings.warn("PRE ATT&CK is deprecated. It will be removed in future versions. Consider adjusting your application")

        pre_filter_objects = {
            "techniques": self.get_pre_techniques,
            "groups": self.get_pre_groups,
            "relationships": self.get_pre_relationships,
            "tactics": self.get_pre_tactics,
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition")
        }
        pre_stix_objects = {}
        for key in pre_filter_objects:
            pre_stix_objects[key] = self.TC_PRE_SOURCE.query(pre_filter_objects[key]) if isinstance(pre_filter_objects[key], Filter) else pre_filter_objects[key]()
            if not stix_format:
                pre_stix_objects[key] = self.translate_stix_objects(pre_stix_objects[key])          
        return pre_stix_objects
    
    def get_pre_techniques(self, skip_revoked_deprecated=True, include_subtechniques=True, stix_format=True):
        """ Extracts all the available techniques STIX objects in the Pre ATT&CK matrix [ DEPRECATED AS OF 11/23/2020 ]

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects. 
            include_subtechniques (bool): default True. Include techniques and sub-techniques STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        
        warnings.warn("PRE ATT&CK is deprecated. It will be removed in future versions. Consider adjusting your application")

        if include_subtechniques:
            pre_techniques = self.TC_PRE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        else:
            pre_techniques = self.TC_PRE_SOURCE.query([
                Filter("type", "=", "attack-pattern"),
                Filter('x_mitre_is_subtechnique', '=', False)
            ])

        if skip_revoked_deprecated:
            pre_techniques = self.remove_revoked_deprecated(pre_techniques)

        if not stix_format:
            pre_techniques = self.translate_stix_objects(pre_techniques)
        return pre_techniques

    def get_pre_groups(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available groups STIX objects in the Pre ATT&CK matrix [ DEPRECATED AS OF 11/23/2020 ]

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        warnings.warn("PRE ATT&CK is deprecated. It will be removed in future versions. Consider adjusting your application")

        pre_groups = self.TC_PRE_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            pre_groups = self.remove_revoked_deprecated(pre_groups)

        if not stix_format:
            pre_groups = self.translate_stix_objects(pre_groups)
        return pre_groups

    def get_pre_relationships(self, stix_format=True):
        """ Extracts all the available relationships STIX objects in the Pre ATT&CK matrix [ DEPRECATED AS OF 11/23/2020 ]

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        warnings.warn("PRE ATT&CK is deprecated. It will be removed in future versions. Consider adjusting your application")

        pre_relationships = self.TC_PRE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            pre_relationships = self.translate_stix_objects(pre_relationships)
        return pre_relationships
    
    def get_pre_tactics(self, stix_format=True):
        """ Extracts all the available tactics STIX objects in the Pre ATT&CK matrix [ DEPRECATED AS OF 11/23/2020 ]

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        warnings.warn("PRE ATT&CK is deprecated. It will be removed in future versions. Consider adjusting your application")

        pre_tactics = self.TC_PRE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            pre_tactics = self.translate_stix_objects(pre_tactics)
        return pre_tactics

    # ******** Mobile ATT&CK Technology Domain  *******
    def get_mobile(self, stix_format=True):
        """ Extracts all the available STIX objects in the Mobile ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        mobile_filter_objects = {
            "techniques": self.get_mobile_techniques,
            "mitigations": self.get_mobile_mitigations,
            "groups": self.get_mobile_groups,
            "malware": self.get_mobile_malware,
            "tools": self.get_mobile_tools,
            "relationships": self.get_mobile_relationships,
            "tactics": self.get_mobile_tactics,
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition"),
            "campaigns": self.get_mobile_campaigns
        }
        mobile_stix_objects = {}
        for key in mobile_filter_objects:
            mobile_stix_objects[key] = self.TC_MOBILE_SOURCE.query(mobile_filter_objects[key]) if isinstance(mobile_filter_objects[key], Filter) else mobile_filter_objects[key]()
            if not stix_format:
                mobile_stix_objects[key] = self.translate_stix_objects(mobile_stix_objects[key])           
        return mobile_stix_objects

    def get_mobile_campaigns(self, skip_revoked_deprecated=True, stix_format=True):
        """  Extracts all the available techniques STIX objects in the Mobile ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects. 
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """

        mobile_campaigns = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "campaign"))

        if skip_revoked_deprecated:
            mobile_campaigns = self.remove_revoked_deprecated(mobile_campaigns)

        if not stix_format:
            mobile_campaigns = self.translate_stix_objects(mobile_campaigns)
        return mobile_campaigns

    def get_mobile_techniques(self, skip_revoked_deprecated=True, include_subtechniques=True, stix_format=True):
        """  Extracts all the available techniques STIX objects in the Mobile ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects. 
            include_subtechniques (bool): default True. Include techniques and sub-techniques STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
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

        if not stix_format:
            mobile_techniques = self.translate_stix_objects(mobile_techniques)
        return mobile_techniques
    
    def get_mobile_mitigations(self, stix_format=True):
        """ Extracts all the available mitigations STIX objects in the Mobile ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        mobile_mitigations = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            mobile_mitigations = self.translate_stix_objects(mobile_mitigations)
        return mobile_mitigations

    def get_mobile_groups(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available groups STIX objects in the Mobile ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        mobile_groups = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            mobile_groups = self.remove_revoked_deprecated(mobile_groups)
          
        if not stix_format:
            mobile_groups = self.translate_stix_objects(mobile_groups)
        return mobile_groups
    
    def get_mobile_malware(self, stix_format=True):
        """ Extracts all the available malware STIX objects in the Mobile ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        mobile_malware = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            mobile_malware = self.translate_stix_objects(mobile_malware)
        return mobile_malware
    
    def get_mobile_tools(self, stix_format=True):
        """Extracts all the available tools STIX objects in the Mobile ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        mobile_tools = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            mobile_tools = self.translate_stix_objects(mobile_tools)
        return mobile_tools

    def get_mobile_relationships(self, stix_format=True):
        """ Extracts all the available relationships STIX objects in the Mobile ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        mobile_relationships = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            mobile_relationships = self.translate_stix_objects(mobile_relationships)
        return mobile_relationships
    
    def get_mobile_tactics(self, stix_format=True):
        """ Extracts all the available tactics STIX objects in the Mobile ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        mobile_tactics = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            mobile_tactics = self.translate_stix_objects(mobile_tactics)
        return mobile_tactics
    
    # ******** ICS ATT&CK Technology Domain *******
    def get_ics(self, stix_format=True):
        """ Extracts all the available STIX objects in the ICS ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        ics_filter_objects = {
            "techniques": self.get_ics_techniques,
            "mitigations": self.get_ics_mitigations,
            "groups": self.get_ics_groups,
            "malware": self.get_ics_malware,
            "relationships": self.get_ics_relationships,
            "tactics": self.get_ics_tactics,
            "matrix": Filter("type", "=", "x-mitre-matrix")
        }
        ics_stix_objects = {}
        for key in ics_filter_objects:
            ics_stix_objects[key] = self.TC_ICS_SOURCE.query(ics_filter_objects[key]) if isinstance(ics_filter_objects[key], Filter) else ics_filter_objects[key]()
            if not stix_format:
                ics_stix_objects[key] = self.translate_stix_objects(ics_stix_objects[key])           
        return ics_stix_objects

    def get_ics_techniques(self, skip_revoked_deprecated=True, include_subtechniques=True, stix_format=True):
        """ Extracts all the available techniques STIX objects in the ICS ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects. 
            include_subtechniques (bool): default True. Include techniques and sub-techniques STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
        
        if not stix_format:
            ics_techniques = self.translate_stix_objects(ics_techniques)
        return ics_techniques

    def get_ics_data_components(self, stix_format=True):
        """ Extracts all the available data components STIX objects in the ICS ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        ics_data_components = self.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-data-component"))
        if not stix_format:
            ics_data_components = self.translate_stix_objects(ics_data_components)
        return ics_data_components

    def get_ics_mitigations(self, stix_format=True):
        """ Extracts all the available mitigations STIX objects in the ICS ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        ics_mitigations = self.TC_ICS_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            ics_mitigations = self.translate_stix_objects(ics_mitigations)
        return ics_mitigations

    def get_ics_groups(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available groups STIX objects in the ICS ATT&CK matrix

        Args:
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        ics_groups = self.TC_ICS_SOURCE.query(Filter("type", "=", "intrusion-set"))

        if skip_revoked_deprecated:
            ics_groups = self.remove_revoked_deprecated(ics_groups)
        
        if not stix_format:
            ics_groups = self.translate_stix_objects(ics_groups)
        return ics_groups

    def get_ics_malware(self, stix_format=True):
        """ Extracts all the available malware STIX objects in the ICS ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        ics_malware = self.TC_ICS_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            ics_malware = self.translate_stix_objects(ics_malware)
        return ics_malware

    def get_ics_relationships(self, stix_format=True):
        """ Extracts all the available relationships STIX objects in the ICS ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        ics_relationships = self.TC_ICS_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            ics_relationships = self.translate_stix_objects(ics_relationships)
        return ics_relationships
    
    def get_ics_tactics(self, stix_format=True):
        """ Extracts all the available tactics STIX objects in the ICS ATT&CK matrix

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        ics_tactics = self.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            ics_tactics = self.translate_stix_objects(ics_tactics)
        return ics_tactics

    def get_ics_data_sources(self, include_data_components=False, stix_format=True):
        """ Extracts all the available data source STIX objects availalbe in the ICS ATT&CK matrix. This function filters all STIX objects by the type x-mitre-data-source.

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        ics_data_sources = self.TC_ICS_SOURCE.query(Filter("type", "=", "x-mitre-data-source"))
        if include_data_components:
            for ds in ics_data_sources:
                ds['data_components']= self.get_data_components_by_data_source(ds)
        if not stix_format:
            ics_data_sources = self.translate_stix_objects(ics_data_sources)
        return ics_data_sources

    # ******** Get All Functions ********
    def get_stix_objects(self, stix_format=True):
        attack_stix_objects = dict()
        attack_stix_objects['enterprise'] = self.get_enterprise()
        attack_stix_objects['mobile'] = self.get_mobile()
        attack_stix_objects['ics'] = self.get_ics()
        
        if not stix_format:
            for matrix in attack_stix_objects.keys():
                for resource_type in attack_stix_objects[matrix].keys():
                    attack_stix_objects[matrix][resource_type] = self.translate_stix_objects(attack_stix_objects[matrix][resource_type])
        return attack_stix_objects

    def get_campaigns(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available campaigns STIX objects across all ATT&CK matrices

        Args: 
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects.
            stix_format (bool): Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        """
        
        enterprise_campaigns = self.get_enterprise_campaigns()
        mobile_campaigns = self.get_mobile_campaigns()
        for mc in mobile_campaigns:
            if mc not in enterprise_campaigns:
                enterprise_campaigns.append(mc)

        if skip_revoked_deprecated:
            enterprise_campaigns = self.remove_revoked_deprecated(enterprise_campaigns)

        if not stix_format:
            enterprise_campaigns = self.translate_stix_objects(enterprise_campaigns)

        return enterprise_campaigns

    def get_techniques(self, include_subtechniques=True, skip_revoked_deprecated=True, enrich_data_sources=False, stix_format=True):
        """ Extracts all the available techniques STIX objects across all ATT&CK matrices

        Args: 
            include_subtechniques (bool): default True. Include techniques and sub-techniques STIX objects.
            skip_revoked_deprecated (bool): default True. Skip revoked and deprecated STIX objects.
            enrich_data_sources (bool): default False. Adds data component and data source context to each technqiue.
            stix_format (bool): Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
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
            all_techniques = self.translate_stix_objects(all_techniques)

        return all_techniques
    
    def get_groups(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available groups STIX objects across all ATT&CK matrices

        Args:
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: Set to True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        all_groups = self.COMPOSITE_DS.query(Filter("type", "=", "intrusion-set"))
        
        if skip_revoked_deprecated:
            all_groups = self.remove_revoked_deprecated(all_groups)
        
        if not stix_format:
            all_groups = self.translate_stix_objects(all_groups)
        return all_groups
   
    def get_mitigations(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available mitigations STIX objects across all ATT&CK matrices
        Args:
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: Set to True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
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
            enterprise_mitigations = self.translate_stix_objects(enterprise_mitigations)
        return enterprise_mitigations

    def get_data_components(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available data components STIX objects across all ATT&CK matrices
        Args:
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: Set to True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        """
        enterprise_data_components = self.get_enterprise_data_components()
        ics_data_components = self.get_ics_data_components()
        '''mobile_data_components = self.get_mobile_data_components()
        for mdc in mobile_data_components:
            if mdc not in enterprise_data_components:
                enterprise_data_components.append(mdc)'''
        for idc in ics_data_components:
            if idc not in enterprise_data_components:
                enterprise_data_components.append(idc)
        
        if skip_revoked_deprecated:
            enterprise_data_components = self.remove_revoked_deprecated(enterprise_data_components)
        
        if not stix_format:
            enterprise_data_components = self.translate_stix_objects(enterprise_data_components)
        return enterprise_data_components

    def get_software(self, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts all the available software STIX objects across all ATT&CK matrices

        Args:
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: Set to True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
            all_software = self.translate_stix_objects(all_software)
        return all_software
   
    def get_relationships(self, relationship_type=None , skip_revoked_deprecated=True, stix_format=True):
        """ Extracts STIX objects of type relationship across all ATT&CK matrices

        Args:
            relationship_type (string): Type of relationship (uses, mitigates, subtechnique-of, detects, revoked-by). Reference: https://github.com/mitre/cti/blob/master/USAGE.md#relationships
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: Set to True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        Returns:
            List of STIX objects
        
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
            all_relationships = self.translate_stix_objects(all_relationships)

        return all_relationships
    
    def get_tactics(self, stix_format=True):
        """ Extracts all the available tactics STIX objects across all ATT&CK matrices

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        all_tactics = self.COMPOSITE_DS.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            all_tactics = self.translate_stix_objects(all_tactics)
        return all_tactics
    
    def get_data_sources(self, include_data_components=False, stix_format=True):
        """ Extracts all the available data source STIX objects availalbe in the ATT&CK TAXII collections. This function filters all STIX objects by the type x-mitre-data-source and also retrieves data components for each data source object.

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        enterprise_data_sources = self.get_enterprise_data_sources(include_data_components)
        ics_data_sources = self.get_ics_data_sources(include_data_components)
        for ds in ics_data_sources:
            if ds not in enterprise_data_sources:
                enterprise_data_sources.append(ds)
        '''
        if include_data_components:
            data_sources = self.get_enterprise_data_sources(include_data_components=True)
        else:
            data_sources = self.get_enterprise_data_sources()'''

        if not stix_format:
            enterprise_data_sources = self.translate_stix_objects(enterprise_data_sources)

        return enterprise_data_sources

    # ******** Custom Functions ********
    def get_technique_by_name(self, name, case=True, stix_format=True):
        """ Extracts technique STIX object by name across all ATT&CK matrices

        Args:
            case (bool) : case sensitive or not
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if not case:
            all_techniques = self.get_techniques()
            all_techniques_list = list()
            for tech in all_techniques:
                if name.lower() in tech['name'].lower():
                    all_techniques_list.append(tech)
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('name', '=', name)
            ]
            all_techniques_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_by_content(self, name, case=True, stix_format=True):
        """ Extracts technique STIX object by content across all ATT&CK matrices

        Args:
            case (bool) : case sensitive or not
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        all_techniques = self.get_techniques()
        all_techniques_list = list()
        for tech in all_techniques:
            if "description" in tech.keys():
                if name.lower() in tech['description'].lower():
                    all_techniques_list.append(tech)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_by_platform(self, name, case=True, stix_format=True ):
        """ Extracts techniques STIX object by platform across all ATT&CK matrices

        Args:
            case (bool) : case sensitive or not
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if not case:
            all_techniques = self.get_techniques()
            all_techniques_list = list()
            for tech in all_techniques:
                if 'x_mitre_platforms' in tech.keys():
                    for platform in tech['x_mitre_platforms']:
                        if name.lower() in platform.lower():
                            all_techniques_list.append(tech)
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('x_mitre_platforms', '=', name)
            ]
            all_techniques_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_by_tactic(self, name, case=True, stix_format=True ):
        """ Extracts techniques STIX objects by tactic accross all ATT&CK matrices

        Args:
            case (bool) : case sensitive or not
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if not case:
            all_techniques = self.get_techniques()
            all_techniques_list = list()
            for tech in all_techniques:
                if 'kill_chain_phases' in tech.keys():
                     if name.lower() in tech['kill_chain_phases'][0]['phase_name'].lower():
                        all_techniques_list.append(tech)
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('kill_chain_phases.phase_name', '=', name)
            ]
            all_techniques_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list

    def get_object_by_attack_id(self, object_type, attack_id, stix_format=True):
        """ Extracts STIX object by attack id accross all ATT&CK matrices

        Args:
            object_type (str) : Object type such as 'attack-pattern' or 'course-of-action' or 'intrusion-set' or 'malware' or 'tool or 'x-mitre-data-component'
            attack_id (str) : STIX object ID
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
                all_stix_objects = self.translate_stix_objects(all_stix_objects)
            return all_stix_objects

    def get_campaign_by_alias(self, campaign_alias, case=True, stix_format=True):
        """ Extracts campaign STIX objects by alias name accross all ATT&CK matrices

        Args:
            campaign_alias (str) : Alias of threat actor group
            case (bool) : case sensitive or not
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if not case:
            all_campaigns = self.get_campaigns()
            all_campaigns_list = list()
            for campaign in all_campaigns:
                if "aliases" in campaign.keys():
                    for alias in campaign['aliases']:
                        if campaign_alias.lower() in alias.lower():
                            all_campaigns_list.append(campaign)
        else:
            filter_objects = [
                Filter('type', '=', 'campaign'),
                Filter('aliases', '=', campaign_alias)
            ]
            all_campaigns_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_campaigns_list = self.translate_stix_objects(all_campaigns_list)
        return all_campaigns_list

    def get_group_by_alias(self, group_alias, case=True, stix_format=True):
        """ Extracts group STIX objects by alias name accross all ATT&CK matrices

        Args:
            group_alias (str) : Alias of threat actor group
            case (bool) : case sensitive or not
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if not case:
            all_groups = self.get_groups()
            all_groups_list = list()
            for group in all_groups:
                if "aliases" in group.keys():
                    for alias in group['aliases']:
                        if group_alias.lower() in alias.lower():
                            all_groups_list.append(group)
        else:
            filter_objects = [
                Filter('type', '=', 'intrusion-set'),
                Filter('aliases', '=', group_alias)
            ]
            all_groups_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_groups_list = self.translate_stix_objects(all_groups_list)
        return all_groups_list

    def get_campaigns_since_time(self, timestamp, stix_format=True):
        """ Extracts campaings STIX objects since specific time accross all ATT&CK matrices

        Args:
            timestamp (timestamp): Timestamp
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        filter_objects = [
            Filter('type', '=', 'campaign'),
            Filter('created', '>', timestamp)
        ]
        all_campaigns_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_campaigns_list = self.translate_stix_objects(all_campaigns_list)
        return all_campaigns_list

    def get_techniques_since_time(self, timestamp, stix_format=True):
        """ Extracts techniques STIX objects since specific time accross all ATT&CK matrices

        Args:
            timestamp (timestamp): Timestamp
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('created', '>', timestamp)
        ]
        all_techniques_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list

    def get_relationships_by_object(self, stix_object, relationship_type=None, source_only=False, target_only=False, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts relationship STIX objects by STIX object accross all ATT&CK matrices

        Args:
            stix_object (stix object): STIX Object to exrtract relationships from.
            relationship_type (string): Type of relationship you want to set as part of the query. Defaulte: None
            source_only (bool): Only retrieve Relationships for which this object is the source_ref. Default: False.
            target_only (bool): Only retrieve Relationships for which this object is the target_ref. Default: False.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
            relationships = self.translate_stix_objects(relationships)
        return relationships
    
    def get_techniques_by_relationship(self, stix_object=None, relationship_type=None, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts techniques targeted by a specific relationship type accross all ATT&CK matrices.

        Args:
            stix_object (STIX object): STIX object whose related relationships will be looked up to find techniques. Default: None
            relationship_type (string): STIX relationship type (e.g. uses, subtechnique-of). Default: None
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: True.
            stix_format (bool): Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
            all_objects = self.translate_stix_objects(all_objects)
        
        return all_objects 
    
    def get_techniques_used_by_group(self, stix_object, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts technique STIX objects used by one group accross all ATT&CK matrices

        Args:
            stix_object (stix object) : STIX Object group to extract techniques from
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        return self.get_techniques_by_relationship(stix_object, None, skip_revoked_deprecated, stix_format )
    
    def get_techniques_used_by_all_groups(self, stix_format=True):
        """ Extracts technique STIX objects used by all groups accross all ATT&CK matrices

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
                    gt['matrix'] =  t['external_references'][0]['source_name']
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
            groups_use_techniques = self.translate_stix_objects(groups_use_techniques)
        return groups_use_techniques

    def get_software_used_by_group(self, stix_object, stix_format=True):
        """ Extracts software STIX objects used by one group accross all ATT&CK matrices

        Args:
            stix_object (stix object) : STIX Object group to extract software from
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        relationships = self.get_relationships_by_object(stix_object, source_only=True)
        software_relationships = list()
        for relation in relationships:
            if get_type_from_id(relation.target_ref) in ['malware', 'tool']:
                software_relationships.append(relation)
        if len(software_relationships) == 0:
            return software_relationships
        filter_objects = [
            Filter('type', 'in', ['malware', 'tool']),
            Filter('id', '=', [r.target_ref for r in software_relationships])
        ]
        all_software = self.COMPOSITE_DS.query(filter_objects)

        if not stix_format:
            all_software = self.translate_stix_objects(all_software)
        return all_software

    def get_techniques_used_by_software(self, stix_object, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts technique STIX objects used by software accross all ATT&CK matrices

        Args:
            stix_object (stix object) : STIX Object software to extract techniques from.
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        return self.get_techniques_by_relationship(stix_object, None, skip_revoked_deprecated, stix_format )
    
    def get_techniques_used_by_group_software(self, stix_object, stix_format=True):
        """ Extracts technique STIX objects used by group software accross all ATT&CK matrices

        Args:
            stix_object (stix object) : STIX Object group software to extract techniques from
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Default: True.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
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
        software_uses = self.COMPOSITE_DS.query.query(filter_objects)
        # Get all techniques used by the software that is used by group
        filter_techniques = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [s.target_ref for s in software_uses])
        ]
        all_techniques_list = self.COMPOSITE_DS.query(filter_techniques)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_mitigated_by_mitigations(self, stix_object=None, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts technique STIX objects mitigated by all or one mitigation accross all ATT&CK matrices

        Args:
            stix_object (stix object): STIX Object mitigation to extract techniques mitigated from. If not provided, it processes all mitigations.
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Set to True by default. 
            stix_format (bool): Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if stix_object:
            all_techniques = self.get_techniques_by_relationship(stix_object, 'mitigates', skip_revoked_deprecated, stix_format)
        else:
            all_techniques = self.get_techniques_by_relationship(relationship_type="mitigates", skip_revoked_deprecated=skip_revoked_deprecated, stix_format=stix_format)

        return all_techniques
    
    def get_techniques_detected_by_data_components(self, stix_object=None, skip_revoked_deprecated=True, stix_format=True):
        """ Extracts technique STIX objects detected by data components accross all ATT&CK matrices

        Args:
            stix_object (stix object): STIX Object data component to extract techniques from. If not provided, it processes all data components.
            skip_revoked_deprecated (bool): removes revoked or deprecated STIX objects from relationships and techniques. Set to True by default.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        if stix_object:
            all_techniques = self.get_techniques_by_relationship(stix_object, 'detects', skip_revoked_deprecated, stix_format)
        else:
            all_techniques = self.get_techniques_by_relationship(relationship_type="detects", skip_revoked_deprecated=skip_revoked_deprecated, stix_format=stix_format)

        return all_techniques

    def get_data_components_by_technique(self, stix_object, stix_format=True):
        """ Extracts data components STIX objects used by one technique accross all ATT&CK matrices

        Args:
            stix_object (stix object) : STIX Object technique to extract data component from
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        relationships = self.get_relationships_by_object(stix_object, relationship_type='detects', target_only=True)
        filter_objects = [
            Filter('type', '=', ['x-mitre-data-component']),
            Filter('id', 'in', [r.source_ref for r in relationships])
        ]
        all_data_components = self.TC_ENTERPRISE_SOURCE.query(filter_objects)

        if not stix_format:
            all_data_components = self.translate_stix_objects(all_data_components)
        return all_data_components

    def get_data_sources_metadata(self):
        """ Extracts data sources metadata from all technique STIX objects accross all ATT&CK matrices. This function uses the x_mitre_data_sources field from attack-pattern objects. This function does NOT retrieve data sources as objects. Data sources as objects are now retrieved by the get_data_sources() function."""
        techniques = self.get_techniques()
        data_sources = []
        for t in techniques:
            if 'x_mitre_data_sources' in t.keys():
                data_sources += [d for d in t['x_mitre_data_sources'] if d not in data_sources]
        return data_sources

    def get_techniques_by_data_sources(self, *args, stix_format=True):
        """ Extracts technique STIX objects by specific data sources accross all ATT&CK matrices

        Args:
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """
        techniques_results = []
        techniques = self.get_techniques()
        for d in args:
            for t in techniques:
                if 'x_mitre_data_sources' in t.keys() and [x for x in t['x_mitre_data_sources'] if d.lower() in x.lower()]:
                    if t not in techniques_results:
                        techniques_results.append(t)
        if not stix_format:
            techniques_results = self.translate_stix_objects(techniques_results)
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
                        "domain": "mitre-enterprise",
                        "versions": {
                            "attack": "10",
                            "navigator": "4.5.5",
                            "layer": "4.3"
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
    
    def  get_data_components_by_data_source(self, stix_object, stix_format=True):
        """ Extracts data component STIX objects referenced by a data source STIX object.

        Args:
            stix_object (stix object) : STIX Object data source to retrieve data component SITX objects from.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        filter_objects = [
            Filter('type', '=', 'x-mitre-data-component'),
            Filter('x_mitre_data_source_ref', '=', stix_object['id'])
        ]
        data_components = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
        if not stix_format:
            data_components = self.translate_stix_objects(data_components)
        return data_components

    def get_data_source_by_data_component(self, stix_object, stix_format=True):
        """ Extracts data source STIX object referenced by a data component STIX object.

        Args:
            stix_object (Stix object) : STIX Object data component to retrieve data source SITX objects from.
            stix_format (bool):  Returns results in original STIX format or friendly syntax (e.g. 'attack-pattern' or 'technique')
        
        Returns:
            List of STIX objects
        
        """

        filter_objects = [
            Filter('type', '=', 'x-mitre-data-source'),
            Filter('id', '=', stix_object['x_mitre_data_source_ref'])
        ]

        data_source = self.COMPOSITE_DS.query(filter_objects)

        if not stix_format:
            data_source = self.translate_stix_objects(data_source)

        return data_source

    def enrich_techniques_data_sources(self, stix_object):
        """ Adds data sources context to STIX Object Technique. It adds data sources with their respective data components identified for each technique.

        Args:
            stix_object (List of stix objects) : List of STIX Object techniques to retrieve data source and data component SITX objects context from.
        Returns:
            List of STIX objects
        
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
        for i in range(len(stix_object)):
            if 'x_mitre_data_sources' in stix_object[i].keys():
                technique_ds = dict()
                for rl in relationships:
                    if stix_object[i]['id'] == rl['target_ref']:
                        dc = dc_lookup[rl['source_ref']]
                        dc_ds_ref = dc['x_mitre_data_source_ref']
                        if dc_ds_ref not in technique_ds.keys():
                            technique_ds[dc_ds_ref] = ds_lookup[dc_ds_ref].copy()
                            technique_ds[dc_ds_ref]['data_components'] = list()
                        if dc not in technique_ds[dc_ds_ref]['data_components']:
                            technique_ds[dc_ds_ref]['data_components'].append(dc)
                if technique_ds:
                    new_data_sources = [ v for v in technique_ds.values()]
                    stix_object[i] = stix_object[i].new_version(x_mitre_data_sources = new_data_sources)
        return stix_object
