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
from stix2.utils import get_type_from_id
from taxii2client.v20 import Collection
import json
import os

ATTCK_STIX_COLLECTIONS = "https://cti-taxii.mitre.org/stix/collections/"
ENTERPRISE_ATTCK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
PRE_ATTCK = "062767bd-02d2-4b72-84ba-56caef0f8658"
MOBILE_ATTCK = "2f669986-b40b-4423-b720-4396ca6a462b"

ENTERPRISE_ATTCK_LOCAL_DIR = "enterprise-attack"
PRE_ATTCK_LOCAL_DIR = "pre-attack"
MOBILE_ATTCK_LOCAL_DIR = "mobile-attack"


class attack_client(object):
    TC_ENTERPRISE_SOURCE = None
    TC_PRE_SOURCE = None
    TC_MOBILE_SOURCE = None
    COMPOSITE_DS = None

    def __init__(self, local_path=None):
        if local_path is not None and os.path.isdir(os.path.join(local_path, ENTERPRISE_ATTCK_LOCAL_DIR)) \
                                  and os.path.isdir(os.path.join(local_path, PRE_ATTCK_LOCAL_DIR)) \
                                  and os.path.isdir(os.path.join(local_path, MOBILE_ATTCK_LOCAL_DIR)):
            self.TC_ENTERPRISE_SOURCE = FileSystemSource(os.path.join(local_path, ENTERPRISE_ATTCK_LOCAL_DIR))
            self.TC_PRE_SOURCE = FileSystemSource(os.path.join(local_path, PRE_ATTCK_LOCAL_DIR))
            self.TC_MOBILE_SOURCE = FileSystemSource(os.path.join(local_path, MOBILE_ATTCK_LOCAL_DIR))
        else:
            ENTERPRISE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + ENTERPRISE_ATTCK + "/")
            PRE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + PRE_ATTCK + "/")
            MOBILE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + MOBILE_ATTCK + "/")

            self.TC_ENTERPRISE_SOURCE = TAXIICollectionSource(ENTERPRISE_COLLECTION)
            self.TC_PRE_SOURCE = TAXIICollectionSource(PRE_COLLECTION)
            self.TC_MOBILE_SOURCE = TAXIICollectionSource(MOBILE_COLLECTION)

        self.COMPOSITE_DS = CompositeDataSource()
        self.COMPOSITE_DS.add_data_sources([self.TC_ENTERPRISE_SOURCE, self.TC_PRE_SOURCE, self.TC_MOBILE_SOURCE])
            
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
                else:
                    exit

                if key in stix_mapping.keys():
                    if key == "external_references" or key == "kill_chain_phases":
                        handle_list(obj_dict[key], key)
                    else:
                        new_key = stix_mapping[key]
                        obj_dict[new_key] = obj_dict.pop(key)
            stix_objects_list.append(obj_dict)
        return stix_objects_list

    def remove_revoked(self, stix_objects, extract=False):
        handle_revoked = list()
        for obj in stix_objects:
            if 'revoked' in obj.keys() and obj['revoked'] == True:
                if extract:
                    handle_revoked.append(obj)
                else:
                    continue
            handle_revoked.append(obj)
        return handle_revoked

    # ******** Enterprise ATT&CK Technology Domain  *******
    def get_enterprise(self, stix_format=True):
        enterprise_filter_objects = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship"),
            "tactics": Filter("type", "=", "x-mitre-tactic"),
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition")
        }
        enterprise_stix_objects = {}
        for key in enterprise_filter_objects:
            enterprise_stix_objects[key] = (self.TC_ENTERPRISE_SOURCE.query(enterprise_filter_objects[key]))
            if not stix_format:
                enterprise_stix_objects[key] = self.translate_stix_objects(enterprise_stix_objects[key])
        return enterprise_stix_objects

    def get_enterprise_techniques(self, stix_format=True):
        enterprise_techniques = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        if not stix_format:
            enterprise_techniques = self.translate_stix_objects(enterprise_techniques)
        return enterprise_techniques
    
    def get_enterprise_mitigations(self, stix_format=True):
        enterprise_mitigations = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            enterprise_mitigations = self.translate_stix_objects(enterprise_mitigations)
        return enterprise_mitigations
    
    def get_enterprise_groups(self, stix_format=True):
        enterprise_groups = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "intrusion-set"))
        if not stix_format:
            enterprise_groups = self.translate_stix_objects(enterprise_groups)
        return enterprise_groups
    
    def get_enterprise_malware(self, stix_format=True):
        enterprise_malware = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            enterprise_malware = self.translate_stix_objects(enterprise_malware)
        return enterprise_malware
    
    def get_enterprise_tools(self, stix_format=True):
        enterprise_tools = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            enterprise_tools = self.translate_stix_objects(enterprise_tools)
        return enterprise_tools
    
    def get_enterprise_relationships(self, stix_format=True):
        enterprise_relationships = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            enterprise_relationships = self.translate_stix_objects(enterprise_relationships)
        return enterprise_relationships
    
    def get_enterprise_tactics(self, stix_format=True):
        enterprise_tactics = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            enterprise_tactics = self.translate_stix_objects(enterprise_tactics)
        return enterprise_tactics

    # ******** Pre ATT&CK Domain  *******
    def get_pre(self, stix_format=True):
        pre_filter_objects = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "groups": Filter("type", "=", "intrusion-set"),
            "relationships": Filter("type", "=", "relationship"),
            "tactics": Filter("type", "=", "x-mitre-tactic"),
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition")
        }
        pre_stix_objects = {}
        for key in pre_filter_objects:
            pre_stix_objects[key] = self.TC_PRE_SOURCE.query(pre_filter_objects[key])
            if not stix_format:
                pre_stix_objects[key] = self.translate_stix_objects(pre_stix_objects[key])           
        return pre_stix_objects

    def get_pre_techniques(self, stix_format=True):
        pre_techniques = self.TC_PRE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        if not stix_format:
            pre_techniques = self.translate_stix_objects(pre_techniques)
        return pre_techniques

    def get_pre_groups(self, stix_format=True):
        pre_groups = self.TC_PRE_SOURCE.query(Filter("type", "=", "intrusion-set"))
        if not stix_format:
            pre_groups = self.translate_stix_objects(pre_groups)
        return pre_groups

    def get_pre_relationships(self, stix_format=True):
        pre_relationships = self.TC_PRE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            pre_relationships = self.translate_stix_objects(pre_relationships)
        return pre_relationships
    
    def get_pre_tactics(self, stix_format=True):
        pre_tactics = self.TC_PRE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            pre_tactics = self.translate_stix_objects(pre_tactics)
        return pre_tactics

    # ******** Mobile ATT&CK Technology Domain  *******
    def get_mobile(self, stix_format=True):
        mobile_filter_objects = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship"),
            "tactics": Filter("type", "=", "x-mitre-tactic"),
            "matrix": Filter("type", "=", "x-mitre-matrix"),
            "identity": Filter("type", "=", "identity"),
            "marking-definition": Filter("type", "=", "marking-definition")
        }
        mobile_stix_objects = {}
        for key in mobile_filter_objects:
            mobile_stix_objects[key] = self.TC_MOBILE_SOURCE.query(mobile_filter_objects[key])
            if not stix_format:
                mobile_stix_objects[key] = self.translate_stix_objects(mobile_stix_objects[key])           
        return mobile_stix_objects
  
    def get_mobile_techniques(self, stix_format=True):
        mobile_techniques = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        if not stix_format:
            mobile_techniques = self.translate_stix_objects(mobile_techniques)
        return mobile_techniques
    
    def get_mobile_mitigations(self, stix_format=True):
        mobile_mitigations = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "course-of-action"))
        if not stix_format:
            mobile_mitigations = self.translate_stix_objects(mobile_mitigations)
        return mobile_mitigations

    def get_mobile_groups(self, stix_format=True):
        mobile_groups = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "intrusion-set"))
        if not stix_format:
            mobile_groups = self.translate_stix_objects(mobile_groups)
        return mobile_groups
    
    def get_mobile_malware(self, stix_format=True):
        mobile_malware = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "malware"))
        if not stix_format:
            mobile_malware = self.translate_stix_objects(mobile_malware)
        return mobile_malware
    
    def get_mobile_tools(self, stix_format=True):
        mobile_tools = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "tool"))
        if not stix_format:
            mobile_tools = self.translate_stix_objects(mobile_tools)
        return mobile_tools

    def get_mobile_relationships(self, stix_format=True):
        mobile_relationships = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "relationship"))
        if not stix_format:
            mobile_relationships = self.translate_stix_objects(mobile_relationships)
        return mobile_relationships
    
    def get_mobile_tactics(self, stix_format=True):
        mobile_tactics = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            mobile_tactics = self.translate_stix_objects(mobile_tactics)
        return mobile_tactics

    # ******** Get All Functions ********
    def get_stix_objects(self, stix_format=True):
        enterprise_objects = self.get_enterprise()
        pre_objects = self.get_pre()
        mobile_objects = self.get_mobile()
        for keypre in pre_objects.keys():
            for preobj in pre_objects[keypre]:
                if keypre in enterprise_objects.keys():
                    if preobj not in enterprise_objects[keypre]:
                        enterprise_objects[keypre].append(preobj)
        for keymob in mobile_objects.keys():
            for mobobj in mobile_objects[keymob]:
                if keymob in enterprise_objects.keys():
                    if mobobj not in enterprise_objects[keymob]:
                        enterprise_objects[keymob].append(mobobj)
        if not stix_format:
            for enterkey in enterprise_objects.keys():
                enterprise_objects[enterkey] = self.translate_stix_objects(enterprise_objects[enterkey])
        return enterprise_objects
    
    def get_techniques(self, stix_format=True):
        all_techniques = self.COMPOSITE_DS.query(Filter("type", "=", "attack-pattern"))
        if not stix_format:
            all_techniques = self.translate_stix_objects(all_techniques)
        return all_techniques
    
    def get_groups(self, stix_format=True):
        all_groups = self.COMPOSITE_DS.query(Filter("type", "=", "intrusion-set"))
        if not stix_format:
            all_groups = self.translate_stix_objects(all_groups)
        return all_groups
   
    def get_mitigations(self, stix_format=True):
        enterprise_mitigations = self.get_enterprise_mitigations()
        mobile_mitigations = self.get_mobile_mitigations()
        for mm in mobile_mitigations:
            if mm not in enterprise_mitigations:
                enterprise_mitigations.append(mm)
        if not stix_format:
            enterprise_mitigations = self.translate_stix_objects(enterprise_mitigations)
        return enterprise_mitigations
    
    def get_software(self, stix_format=True):
        enterprise_malware = self.get_enterprise_malware()
        enterprise_tools = self.get_enterprise_tools()
        mobile_malware = self.get_mobile_malware()
        mobile_tools = self.get_mobile_tools()
        for mt in mobile_tools:
            if mt not in enterprise_tools:
                enterprise_tools.append(mt)
        for mmal in mobile_malware:
            if mmal not in enterprise_malware:
                enterprise_malware.append(mmal)
        all_software = enterprise_tools + enterprise_malware
        if not stix_format:
            all_software = self.translate_stix_objects(all_software)
        return all_software
   
    def get_relationships(self, stix_format=True):
        all_relationships = self.COMPOSITE_DS.query(Filter("type", "=", "relationship"))
        if not stix_format:
            all_relationships = self.translate_stix_objects(all_relationships)
        return all_relationships
    
    def get_tactics(self, stix_format=True):
        all_tactics = self.COMPOSITE_DS.query(Filter("type", "=", "x-mitre-tactic"))
        if not stix_format:
            all_tactics = self.translate_stix_objects(all_tactics)
        return all_tactics

    # ******** Custom Functions ********
    def get_technique_by_name(self, name, case=True, stix_format=True):
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
        valid_objects = {'attack-pattern','course-of-action','intrusion-set','malware','tool'}
        if object_type not in valid_objects:
            raise ValueError("ERROR: Valid object must be one of %r" % valid_objects)
        else:
            filter_objects = [
                Filter('type', '=', object_type),
                Filter('external_references.external_id', '=', attack_id)
            ]
            all_stix_objects = self.COMPOSITE_DS.query(filter_objects)
            if not stix_format:
                all_stix_objects = self.translate_stix_objects(all_stix_objects)
            return all_stix_objects

    def get_group_by_alias(self, group_alias, case=True, stix_format=True):
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
    
    def get_techniques_since_time(self, timestamp, stix_format=True):
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('created', '>', timestamp)
        ]
        all_techniques_list = self.COMPOSITE_DS.query(filter_objects)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list

    def get_relationships_by_object(self, stix_object, stix_format=True):
        if stix_object['type'] == 'course-of-action':
            relationships = self.COMPOSITE_DS.relationships(stix_object, 'mitigates', source_only=True)
        else:
            relationships = self.COMPOSITE_DS.relationships(stix_object, 'uses', source_only=True)
        if not stix_format:
            relationships = self.translate_stix_objects(relationships)
        return relationships
    
    def get_techniques_used_by_group(self, stix_object, stix_format=True):
        relationships = self.get_relationships_by_object(stix_object)
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', '=', [r.target_ref for r in relationships])
        ]
        try:
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
        except:
            enterprise_stix_objects = []
        try:
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
        except:
            pre_stix_objects = []
        try:
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
        except:
            mobile_stix_objects = []
        all_techniques_list = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_used_by_all_groups(self, stix_format=True):
        groups = self.get_groups()
        groups = self.remove_revoked(groups)
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
                    tactic_list = list()
                    for phase in t['kill_chain_phases']:
                        tactic_list.append(phase['phase_name'])
                    gt['technique'] = t['name']
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
        relationships = self.get_relationships_by_object(stix_object)
        software_relationships = list()
        for relation in relationships:
            if get_type_from_id(relation.target_ref) in ['malware', 'tool']:
                software_relationships.append(relation)
        filter_objects = [
            Filter('type', 'in', ['malware', 'tool']),
            Filter('id', '=', [r.target_ref for r in software_relationships])
        ]
        try:
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
        except:
            enterprise_stix_objects = []
        try:
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
        except:
            pre_stix_objects = []
        try:
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
        except:
            mobile_stix_objects = []
        all_software_list = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
        if not stix_format:
            all_software_list = self.translate_stix_objects(all_software_list)
        return all_software_list

    def get_techniques_used_by_software(self, stix_object, stix_format=True):
        relationships = self.get_relationships_by_object(stix_object)
        software_relationships = list()
        for relation in relationships:
            if get_type_from_id(relation.source_ref) in ['malware', 'tool']:
                software_relationships.append(relation)
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', '=', [r.target_ref for r in software_relationships])
        ]
        try:
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
        except:
            enterprise_stix_objects = []
        try:
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
        except:
            pre_stix_objects = []
        try:
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
        except:
            mobile_stix_objects = []
        all_techniques_list = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_used_by_group_software(self, stix_object, stix_format=True):
        # Get all relationships available for group
        relationships = self.get_relationships_by_object(stix_object)
        software_relationships = list()
        # Get all software relationships from group
        for relation in relationships:
            if get_type_from_id(relation.target_ref) in ['malware', 'tool']:
                software_relationships.append(relation)
        # Get all used by the software that is used by group
        filter_objects = [
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', 'in', [r.target_ref for r in software_relationships])
        ]
        try:
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
        except:
            enterprise_stix_objects = []
        try:
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
        except:
            pre_stix_objects = []
        try:
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
        except:
            mobile_stix_objects = []
        software_uses = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
        # Get all techniques used by the software that is used by group
        filter_techniques = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', 'in', [s.target_ref for s in software_uses])
        ]
        try:
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_techniques)
        except:
            enterprise_stix_objects = []
        try:
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_techniques)
        except:
            pre_stix_objects = []
        try:
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_techniques)
        except:
            mobile_stix_objects = []
        all_techniques_list = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_mitigated_by_mitigation(self, stix_object, stix_format=True):
        relationships = self.get_relationships_by_object(stix_object)
        mitigation_relationships = list()
        for relation in relationships:
            if get_type_from_id(relation.source_ref) == 'course-of-action':
                mitigation_relationships.append(relation)
        filter_objects = [
            Filter('type', '=', 'attack-pattern'),
            Filter('id', '=', [r.target_ref for r in mitigation_relationships])
        ]
        try:
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
        except:
            enterprise_stix_objects = []
        try:
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
        except:
            pre_stix_objects = []
        try:
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
        except:
            mobile_stix_objects = []
        all_techniques_list = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list
    
    def get_techniques_mitigated_by_all_mitigations(self, stix_format=True):
        # Get all relationships available
        relationships = self.get_relationships()
        # Get all mitigation relationships
        mitigation_relationships = list()
        for relation in relationships:
            if get_type_from_id(relation.source_ref) in ['course-of-action']:
                mitigation_relationships.append(relation)
        # Get all techniques
        techniques = self.get_techniques()
        all_techniques_list = list()
        # loop through mitigation relationships to match technique
        for mr in mitigation_relationships:
            for t in techniques:
                if t['id'] == mr['target_ref']:
                    all_techniques_list.append(t)
        if not stix_format:
            all_techniques_list = self.translate_stix_objects(all_techniques_list)
        return all_techniques_list

    def get_data_sources(self):
        techniques = self.get_techniques()
        data_sources = []
        for t in techniques:
            if 'x_mitre_data_sources' in t.keys():
                data_sources += [d for d in t['x_mitre_data_sources'] if d not in data_sources]
        return data_sources

    def get_techniques_by_datasources(self, *args, stix_format=True):
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
        techniques_used = self.get_techniques_used_by_all_groups()
        groups = self.get_groups()
        groups = self.remove_revoked(groups)
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
                        "version": "2.2",
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