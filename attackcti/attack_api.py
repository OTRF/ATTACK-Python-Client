#!/usr/bin/env python

# ATT&CK Client Main Script
# Author: Roberto Rodriguez (@Cyb3rWard0g)
# License: BSD 3-Clause
# Reference:
# https://www.mitre.org/capabilities/cybersecurity/overview/cybersecurity-blog/attck%E2%84%A2-content-available-in-stix%E2%84%A2-20-via
# https://github.com/mitre/cti/blob/master/USAGE.md

from stix2 import TAXIICollectionSource, Filter
from taxii2client import Server, Collection

ATTCK_STIX_COLLECTIONS = "https://cti-taxii.mitre.org/stix/collections/"
ENTERPRISE_ATTCK = "95ecc380-afe9-11e4-9b6c-751b66dd541e"
PRE_ATTCK = "062767bd-02d2-4b72-84ba-56caef0f8658"
MOBILE_ATTCK = "2f669986-b40b-4423-b720-4396ca6a462b"

class attack_client(object):
    ENTERPRISE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + ENTERPRISE_ATTCK + "/")
    TC_ENTERPRISE_SOURCE = TAXIICollectionSource(ENTERPRISE_COLLECTION)
    PRE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + PRE_ATTCK + "/")
    TC_PRE_SOURCE = TAXIICollectionSource(PRE_COLLECTION)
    MOBILE_COLLECTION = Collection(ATTCK_STIX_COLLECTIONS + MOBILE_ATTCK + "/")
    TC_MOBILE_SOURCE = TAXIICollectionSource(MOBILE_COLLECTION)

    # ******** Helper Functions ********
    def parse_stix_objects(self, stix_objects, stix_object_type):
        stix_objects_list = list()
        if stix_object_type == 'techniques':
            for technique in stix_objects:
                technique_dict = {
                    'type': technique['type'],
                    'id': technique['id'],
                    'created_by_ref': self.try_except(technique,'created_by_ref'),
                    'created': str(technique['created']),
                    'modified': str(technique['modified']),
                    'object_marking_refs': self.try_except(technique,'object_marking_refs'),
                    'url': technique['external_references'][0]['url'],
                    'matrix': technique['external_references'][0]['source_name'],
                    'technique': technique['name'],
                    'technique_description': self.try_except(technique, 'description'),
                    'technique_detection': self.try_except(technique, 'x_mitre_detection'),
                    'tactic': self.try_except(technique,'kill_chain_phases','phase_name'),
                    'technique_id': technique['external_references'][0]['external_id'],
                    'capec_id': self.try_except(technique,'external_references','capec_id'),
                    'capec_url': self.try_except(technique,'external_references','capec_url'),
                    'platform': self.try_except(technique,'x_mitre_platforms'),
                    'data_sources': self.try_except(technique,'x_mitre_data_sources'),
                    'defense_bypassed': self.try_except(technique,'x_mitre_defense_bypassed'),
                    'permissions_required': self.try_except(technique,'x_mitre_permissions_required'),
                    'effective_permissions': self.try_except(technique,'x_mitre_effective_permissions'),
                    'system_requirements': self.try_except(technique,'x_mitre_system_requirements'),
                    'network_requirements': self.try_except(technique,'x_mitre_network_requirements'),
                    'remote_support': self.try_except(technique,'x_mitre_remote_support'),
                    'contributors': self.try_except(technique,'x_mitre_contributors'),
                    'technique_references': self.try_except(technique,'external_references'),
                    'detectable_by_common_defenses': self.try_except(technique,'x_mitre_detectable_by_common_defenses'),
                    'detectable_explanation': self.try_except(technique,'x_mitre_detectable_by_common_defenses_explanation'),
                    'difficulty_for_adversary': self.try_except(technique,'x_mitre_difficulty_for_adversary'),
                    'difficulty_explanation': self.try_except(technique,'x_mitre_difficulty_for_adversary_explanation'),
                    'tactic_type': self.try_except(technique,'x_mitre_tactic_type')
                }
                stix_objects_list.append(technique_dict)
        elif stix_object_type == "mitigations":
            for mitigation in stix_objects:
                mitigation_dict = {
                    'type': mitigation['type'],
                    'id': mitigation['id'],
                    'created_by_ref': mitigation['created_by_ref'],
                    'created': str(mitigation['created']),
                    'modified': str(mitigation['modified']),
                    'matrix': mitigation['external_references'][0]['source_name'],
                    'url': mitigation['external_references'][0]['url'],
                    'mitigation': mitigation['name'],
                    'mitigation_description': mitigation['description'],
                    'technique_id': mitigation['external_references'][0]['external_id'],
                    'mitigation_references': self.handle_list(mitigation,'external_references')
                }
                stix_objects_list.append(mitigation_dict)
        elif stix_object_type == "groups":
            for group in stix_objects:
                group_dict = {
                    'type': group['type'],
                    'id': group['id'],
                    'created_by_ref': self.try_except(group, 'created_by_ref'),
                    'matrix': group['external_references'][0]['source_name'],
                    'created': str(group['created']),
                    'modified': str(group['modified']),
                    'url': group['external_references'][0]['url'],
                    'group': group['name'],
                    'group_description': self.try_except(group, 'description'),
                    'group_aliases': self.try_except(group, 'aliases'),
                    'group_id': group['external_references'][0]['external_id'],
                    'group_references': self.try_except(group,'external_references')
                }
                stix_objects_list.append(group_dict)
        elif stix_object_type == "tools" or stix_object_type == "malware" or stix_object_type == "software":
             for software in stix_objects:
                software_dict = {
                    'type': software['type'],
                    'id': software['id'],
                    'created_by_ref': self.try_except(software, 'created_by_ref'),
                    'created': str(software['created']),
                    'modified': str(software['modified']),
                    'matrix': software['external_references'][0]['source_name'],
                    'software': software['name'],
                    'software_description': self.try_except(software, 'description'),
                    'software_labels': self.try_except(software, 'labels'),
                    'software_id': software['external_references'][0]['external_id'],
                    'url': software['external_references'][0]['url'],
                    'software_aliases': self.try_except(software, 'x_mitre_aliases'),
                    'software_references': self.try_except(software,'external_references'),
                    'software_platform': self.try_except(software, 'x_mitre_platforms')
                }
                stix_objects_list.append(software_dict)
        elif stix_object_type == "relationships":
            for relationship in stix_objects:
                relationship_dict = {
                    'type': relationship['type'],
                    'id': relationship['id'],
                    'created_by_ref': relationship['created_by_ref'],
                    'created': str(relationship['created']),
                    'modified': str(relationship['modified']),
                    'relationship': relationship['relationship_type'],
                    'relationship_description': self.try_except(relationship, 'description'),
                    'source_object': relationship['source_ref'],
                    'target_object': relationship['target_ref']
                }
                stix_objects_list.append(relationship_dict)
        else:
            exit

        return stix_objects_list

    def handle_list(self, stix_objects, object_type):
        objects_list = list()
        if object_type == 'external_references':
            for o in stix_objects[object_type]:
                if "url" in o:
                    objects_list.append(o.url)
                else:
                    objects_list.append(o.source_name)
        else:
            for o in stix_objects[object_type]:
                    objects_list.append(o)
        return objects_list
    
    def handle_nested(self, stix_objects, object_type, nested_value):
        objects_list = list()
        if object_type == 'external_references' and nested_value == 'capec_id':
            for o in stix_objects[object_type]:
                if o.source_name == 'capec':
                    objects_list.append(o.external_id)
        elif object_type == 'external_references' and nested_value == 'capec_url':
            for o in stix_objects[object_type]:
                if o.source_name == 'capec':
                    objects_list.append(o.url)
        else:
            for o in stix_objects[object_type]:
                if nested_value in o:
                    objects_list.append(o[nested_value])
        if not objects_list:
            return None
        else:
            return objects_list

    def try_except(self, stix_objects, object_type, nested_value=None):
        if object_type in stix_objects:
            specific_stix_object = stix_objects[object_type]
            if isinstance(specific_stix_object, list):
                if nested_value is None:
                    lists = self.handle_list(stix_objects, object_type)
                    return lists
                else:
                    nested_result = self.handle_nested(stix_objects, object_type, nested_value)
                    return nested_result
            else:
                return stix_objects[object_type]
        else:
            return None

    # ******** Get All Functions ********
    def get_all_stix_objects(self):
        techniques_pre_keys = {"techniques","groups","relationships"}
        techniques_mobile_keys = {"techniques","mitigations","groups","malware","tools","relationships"}
        enterprise_objects = self.get_all_enterprise()
        pre_objects = self.get_all_pre()
        mobile_objects = self.get_all_mobile()
        for key in techniques_pre_keys:
            for pre in pre_objects[key]:
                if pre not in enterprise_objects[key]:
                    enterprise_objects[key].append(pre)
        for key in techniques_mobile_keys:
            for m in mobile_objects[key]:
                if m not in enterprise_objects[key]:
                    enterprise_objects[key].append(m)
        return enterprise_objects

    def get_all_attack(self):       
        techniques = self.get_all_techniques_with_mitigations()
        software = self.get_all_software()
        software_use = self.get_techniques_used_by_software()
        groups = self.get_all_groups()
        groups_use = self.get_all_used_by_group()
        for s in software:
            del s['type'],s['id'],s['created_by_ref'],s['created'],s['modified']
        for g in groups:
            del g['type'],g['id'],g['created_by_ref'],g['created'],g['modified']
        all_attack = techniques + software + software_use + groups + groups_use
        return all_attack

    def get_all_enterprise(self):
        enterprise_filter_objects = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship")
        }
        enterprise_stix_objects = {}
        for key in enterprise_filter_objects:
            enterprise_stix_objects[key] = self.TC_ENTERPRISE_SOURCE.query(enterprise_filter_objects[key])
            enterprise_stix_objects[key] = self.parse_stix_objects(enterprise_stix_objects[key], key)
        return enterprise_stix_objects

    def get_all_pre(self):
        pre_filter_objects = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "groups": Filter("type", "=", "intrusion-set"),
            "relationships": Filter("type", "=", "relationship")
        }
        pre_stix_objects = {}
        for key in pre_filter_objects:
            pre_stix_objects[key] = self.TC_PRE_SOURCE.query(pre_filter_objects[key])
            pre_stix_objects[key] = self.parse_stix_objects(pre_stix_objects[key], key)           
        return pre_stix_objects

    def get_all_mobile(self):
        mobile_filter_objects = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship")
        }
        mobile_stix_objects = {}
        for key in mobile_filter_objects:
            mobile_stix_objects[key] = self.TC_MOBILE_SOURCE.query(mobile_filter_objects[key])
            mobile_stix_objects[key] = self.parse_stix_objects(mobile_stix_objects[key], key)           
        return mobile_stix_objects

    def get_all_techniques(self):
        enterprise_techniques = self.get_all_enterprise_techniques()
        pre_techniques = self.get_all_pre_techniques()
        mobile_techniques = self.get_all_mobile_techniques()
        all_techniques = enterprise_techniques + pre_techniques + mobile_techniques
        return all_techniques
    
    def get_all_groups(self):
        enterprise_groups = self.get_all_enterprise_groups()
        pre_groups = self.get_all_pre_groups()
        mobile_groups = self.get_all_mobile_groups()
        for pg in pre_groups:
            if pg not in enterprise_groups:
                enterprise_groups.append(pg)
        for mg in mobile_groups:
            if mg not in enterprise_groups:
                enterprise_groups.append(mg)
        return enterprise_groups
   
    def get_all_mitigations(self):
        enterprise_mitigations = self.get_all_enterprise_mitigations()
        mobile_mitigations = self.get_all_mobile_mitigations()
        for mm in mobile_mitigations:
            if mm not in enterprise_mitigations:
                enterprise_mitigations.append(mm)
        return enterprise_mitigations
    
    def get_all_software(self):
        enterprise_malware = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "malware"))
        enterprise_tools = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "tool"))
        mobile_malware = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "malware"))
        mobile_tools = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "tool"))
        for mt in mobile_tools:
            if mt not in enterprise_tools:
                enterprise_tools.append(mt)
        for mmal in mobile_malware:
            if mmal not in enterprise_malware:
                enterprise_malware.append(mmal)
        all_software = enterprise_tools + enterprise_malware
        all_software = self.parse_stix_objects(all_software, 'software')
        return all_software
   
    def get_all_relationships(self):
        enterprise_relationships = self.get_all_enterprise_relationships()
        pre_relationships = self.get_all_pre_relationships()
        mobile_relationships = self.get_all_mobile_relationships()
        for pr in pre_relationships:
            if pr not in enterprise_relationships:
                enterprise_relationships.append(pr)
        for mr in mobile_relationships:
            if mr not in enterprise_relationships:
                enterprise_relationships.append(mr)
        return enterprise_relationships

    def get_all_techniques_with_mitigations(self):
        all_mitigations_mitigate = []
        technique_ids = []
        all_mitigations_relationships = self.get_relationships_by_object('mitigations')
        techniques = self.get_all_techniques()
        for mr in all_mitigations_relationships:
            for t in techniques:
                if t['id'] == mr['target_object']:
                    all_mitigations_dict = {
                        'matrix': t['matrix'],
                        'mitigation': mr['mitigation'],
                        'mitigation_description': mr['mitigation_description'],
                        'mitigation_references': mr['mitigation_references'],
                        'technique': t['technique'],
                        'technique_description': t['technique_description'],
                        'technique_detection': t['technique_detection'],
                        'tactic' : t['tactic'],
                        'url' : t['url'],
                        'technique_id' : t['technique_id'],
                        'capec_id': t['capec_id'],
                        'capec_url': t['capec_url'],
                        'platform' : t['platform'],
                        'data_sources' : t['data_sources'],
                        'defense_bypassed' : t['defense_bypassed'],
                        'permissions_required' : t['permissions_required'],
                        'effective_permissions' : t['effective_permissions'],
                        'system_requirements' : t['system_requirements'],
                        'network_requirements' : t['network_requirements'],
                        'remote_support' : t['remote_support'],
                        'contributors' : t['contributors'],
                        'technique_references' : t['technique_references'],
                        'detectable_by_common_defenses' : t['detectable_by_common_defenses'],
                        'detectable_explanation' : t['detectable_explanation'],
                        'difficulty_for_adversary' : t['difficulty_for_adversary'],
                        'difficulty_explanation': t['difficulty_explanation'],
                        'tactic_type' : t['tactic_type']
                    }
                    all_mitigations_mitigate.append(all_mitigations_dict)
                    technique_ids.append(t['technique_id'])
        for t in techniques:
            if t['technique_id'] not in technique_ids:
                all_mitigations_mitigate.append(t)
        return all_mitigations_mitigate

# ******** Enterprise Matrix Functions ********
    def get_all_enterprise_techniques(self):
        enterprise_techniques = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        enterprise_techniques = self.parse_stix_objects(enterprise_techniques, 'techniques')
        return enterprise_techniques

    def get_all_enterprise_groups(self):
        enterprise_groups = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "intrusion-set"))
        enterprise_groups = self.parse_stix_objects(enterprise_groups, 'groups')
        return enterprise_groups

    def get_all_enterprise_mitigations(self):
        enterprise_mitigations = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "course-of-action"))
        enterprise_mitigations = self.parse_stix_objects(enterprise_mitigations, 'mitigations')
        return enterprise_mitigations

    def get_all_enterprise_relationships(self):
        enterprise_relationships = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "relationship"))
        enterprise_relationships = self.parse_stix_objects(enterprise_relationships, 'relationships')
        return enterprise_relationships

# ******** Pre Matrix Functions ********
    def get_all_pre_techniques(self):
        pre_techniques = self.TC_PRE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        pre_techniques = self.parse_stix_objects(pre_techniques, 'techniques')
        return pre_techniques

    def get_all_pre_groups(self):
        pre_groups = self.TC_PRE_SOURCE.query(Filter("type", "=", "intrusion-set"))
        pre_groups = self.parse_stix_objects(pre_groups, 'groups')
        return pre_groups

    def get_all_pre_relationships(self):
        pre_relationships = self.TC_PRE_SOURCE.query(Filter("type", "=", "relationship"))
        pre_relationships = self.parse_stix_objects(pre_relationships, 'relationships')
        return pre_relationships

# ******** Mobile Matrix Functions ********   
    def get_all_mobile_techniques(self):
        mobile_techniques = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "attack-pattern"))
        mobile_techniques = self.parse_stix_objects(mobile_techniques, 'techniques')
        return mobile_techniques

    def get_all_mobile_groups(self):
        mobile_groups = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "intrusion-set"))
        mobile_groups = self.parse_stix_objects(mobile_groups, 'groups')
        return mobile_groups

    def get_all_mobile_mitigations(self):
        mobile_mitigations = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "course-of-action"))
        mobile_mitigations = self.parse_stix_objects(mobile_mitigations, 'mitigations')
        return mobile_mitigations

    def get_all_mobile_relationships(self):
        mobile_relationships = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "relationship"))
        mobile_relationships = self.parse_stix_objects(mobile_relationships, 'relationships')
        return mobile_relationships

# ******** Custom Functions ********
    def get_technique_by_name(self, name, case=True):
        if not case:
            all_techniques = self.get_all_techniques()
            for tech in all_techniques:
                if name.lower() in tech['technique'].lower():
                    return tech
        else:
            filter_objects = [
                Filter('type', '=', 'attack-pattern'),
                Filter('name', '=', name)
            ]
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
            all_stix_objects = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
            all_stix_objects = self.parse_stix_objects(all_stix_objects, "techniques")
            return all_stix_objects

    def get_object_by_attack_id(self, object_type, attack_id):
        valid_objects = {'attack-pattern','course-of-action','intrusion-set','malware','tool'}
        if object_type not in valid_objects:
            raise ValueError("ERROR: Valid object must be one of %r" % valid_objects)
        else:
            dictionary = {
                "attack-pattern": "techniques",
                "course-of-action": "mitigations",
                "intrusion-set": "groups",
                "malware": "malware",
                "tool": "tools"
            }
            filter_objects = [
                Filter('type', '=', object_type),
                Filter('external_references.external_id', '=', attack_id)
            ]
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
            enterprise_stix_objects = self.parse_stix_objects(enterprise_stix_objects, dictionary[object_type])
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
            pre_stix_objects = self.parse_stix_objects(pre_stix_objects, dictionary[object_type])
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
            mobile_stix_objects = self.parse_stix_objects(mobile_stix_objects, dictionary[object_type])
            all_stix_objects = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
            return all_stix_objects

    def get_group_by_alias(self, group_alias, case=True):
        if not case:
            all_groups = self.get_all_groups()
            for group in all_groups:
                if group_alias.lower() in group['group_aliases'].lower():
                    return group
        else:
            filter_objects = [
                Filter('type', '=', 'intrusion-set'),
                Filter('aliases', '=', group_alias)
            ]
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objects)
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objects)
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objects)
            all_stix_objects = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
            all_stix_objects = self.parse_stix_objects(all_stix_objects, 'groups')
            return all_stix_objects

    def get_relationships_by_object(self, stix_object):
        valid_objects = {'groups','software','mitigations'}
        all_relationships = []
        relationships = self.get_all_relationships()
        if stix_object not in valid_objects:
            raise ValueError("ERROR: Valid object must be one of %r" % valid_objects)
        else:
            if stix_object.lower() == 'groups':
                groups = self.get_all_groups()
                for g in groups:
                    for r in relationships:
                        if g['id'] == r['source_object'] and r['relationship'] == 'uses':
                            all_groups_relationships_dict = {
                                'target_object' : r['target_object'],
                                'relationship_id': r['id'],
                                'relationship': r['relationship'],
                                'relationship_description' : r['relationship_description'],
                                'matrix': g['matrix'],
                                'url': g['url'],
                                'group': g['group'],
                                'group_description': g['group_description'],
                                'group_aliases': g['group_aliases'],
                                'group_id': g['group_id'],
                                'group_references': g['group_references']
                            }
                            all_relationships.append(all_groups_relationships_dict)
            elif stix_object.lower() == 'software':
                software = self.get_all_software()
                relationships = self.get_all_relationships()
                for s in software:
                    for r in relationships:
                        if s['id'] == r['source_object'] and r['relationship'] == 'uses':
                            all_software_relationships_dict = {
                                'target_object' : r['target_object'],
                                'relationship_id': r['id'],
                                'relationship': r['relationship'],
                                'relationship_description' : r['relationship_description'],
                                'software_type': s['type'],
                                'matrix': s['matrix'],
                                'software': s['software'],
                                'software_description': s['software_description'],
                                'software_labels':s['software_labels'],
                                'software_id': s['software_id'],
                                'url': s['url'],
                                'software_aliases': s['software_aliases'],
                                'software_references': s['software_references'],
                                'software_platform': s['software_platform']
                            }
                            all_relationships.append(all_software_relationships_dict)
            else:
                mitigations = self.get_all_mitigations()
                relationships = self.get_all_relationships()
                for m in mitigations:
                    for r in relationships:
                        if m['id'] == r['source_object'] and r['relationship'] == 'mitigates':
                            all_mitigations_relationships_dict = {
                                'target_object' : r['target_object'],
                                'relationship_id': r['id'],
                                'relationship': r['relationship'],
                                'relationship_description' : r['relationship_description'],   
                                'matrix': m['matrix'],
                                'mitigation': m['mitigation'],
                                'mitigation_description': m['mitigation_description'],
                                'mitigation_references': m['mitigation_references']
                            }
                            all_relationships.append(all_mitigations_relationships_dict)
            return all_relationships

    def get_techniques_used_by_software(self, software_name=None, case=True):
        all_software_use = []
        all_techniques_used = []
        all_software_relationships = self.get_relationships_by_object('software')
        techniques = self.get_all_techniques()
        for sr in all_software_relationships:
            for t in techniques:
                if t['id'] == sr['target_object']:
                    all_software_use_dict = {
                        'matrix': t['matrix'],
                        'relationship_id': sr['relationship_id'],
                        'target_object': sr['target_object'],
                        'relationship_description': sr['relationship_description'],
                        'relationship': sr['relationship'],
                        'software': sr['software'],
                        'software_description': sr['software_description'],
                        'software_labels':sr['software_labels'],
                        'software_id': sr['software_id'],
                        'software_aliases': sr['software_aliases'],
                        'software_references': sr['software_references'],
                        'software_platform': sr['software_platform'],
                        'technique': t['technique'],
                        'technique_description': t['technique_description'],
                        'technique_detection': t['technique_detection'],
                        'tactic' : t['tactic'],
                        'url' : t['url'],
                        'technique_id' : t['technique_id'],
                        'capec_id': t['capec_id'],
                        'capec_url': t['capec_url'],
                        'platform' : t['platform'],
                        'data_sources' : t['data_sources'],
                        'defense_bypassed' : t['defense_bypassed'],
                        'permissions_required' : t['permissions_required'],
                        'effective_permissions' : t['effective_permissions'],
                        'system_requirements' : t['system_requirements'],
                        'network_requirements' : t['network_requirements'],
                        'remote_support' : t['remote_support'],
                        'contributors' : t['contributors'],
                        'technique_references' : t['technique_references'],
                        'detectable_by_common_defenses' : t['detectable_by_common_defenses'],
                        'detectable_explanation' : t['detectable_explanation'],
                        'difficulty_for_adversary' : t['difficulty_for_adversary'],
                        'difficulty_explanation': t['difficulty_explanation'],
                        'tactic_type' : t['tactic_type']
                    }
                    all_software_use.append(all_software_use_dict)
        if software_name is None:
            return all_software_use
        else:
            if not case:
                for sn in all_software_use:
                    if software_name.lower() in sn['software'].lower():
                        all_techniques_used.append(sn)
            else:
                for sn in all_software_use:
                    if software_name in sn['software']:
                        all_techniques_used.append(sn)
            return all_techniques_used
    
    def get_techniques_used_by_group(self, group_name=None):
        all_groups_use = []
        all_techniques_used = []
        all_groups_relationships = self.get_relationships_by_object('groups')
        techniques = self.get_all_techniques()
        for gr in all_groups_relationships:
            for t in techniques:
                if t['id'] == gr['target_object']:
                    all_groups_use_dict = {
                        'matrix': t['matrix'],
                        'relationship_id': gr['relationship_id'],
                        'target_object': gr['target_object'],
                        'relationship_description': gr['relationship_description'],
                        'relationship': gr['relationship'],
                        'group': gr['group'],
                        'group_description': gr['group_description'],
                        'group_aliases': gr['group_aliases'],
                        'group_id': gr['group_id'],
                        'group_references': gr['group_references'],
                        'technique': t['technique'],
                        'technique_description': t['technique_description'],
                        'technique_detection': t['technique_detection'],
                        'tactic' : t['tactic'],
                        'url' : t['url'],
                        'technique_id' : t['technique_id'],
                        'capec_id': t['capec_id'],
                        'capec_url': t['capec_url'],
                        'platform' : t['platform'],
                        'data_sources' : t['data_sources'],
                        'defense_bypassed' : t['defense_bypassed'],
                        'permissions_required' : t['permissions_required'],
                        'effective_permissions' : t['effective_permissions'],
                        'system_requirements' : t['system_requirements'],
                        'network_requirements' : t['network_requirements'],
                        'remote_support' : t['remote_support'],
                        'contributors' : t['contributors'],
                        'technique_references' : t['technique_references'],
                        'detectable_by_common_defenses' : t['detectable_by_common_defenses'],
                        'detectable_explanation' : t['detectable_explanation'],
                        'difficulty_for_adversary' : t['difficulty_for_adversary'],
                        'difficulty_explanation': t['difficulty_explanation'],
                        'tactic_type' : t['tactic_type']
                    }
                    all_groups_use.append(all_groups_use_dict)
        if group_name is None:
            return all_groups_use
        else:
            for gn in all_groups_use:
                if group_name.lower() in gn['group'].lower():
                    all_techniques_used.append(gn)
            return all_techniques_used

    def get_software_used_by_group(self, group_name=None):
        all_groups_software_use =[]
        all_groups_use = []
        all_software_used = []
        all_groups_relationships = self.get_relationships_by_object('groups')
        software_techniques = self.get_techniques_used_by_software()
        software = self.get_all_software()
        for gr in all_groups_relationships:
            for s in software:
                if s['id'] == gr['target_object']:
                    all_groups_software = {
                        'matrix': s['matrix'],
                        'relationship_description': gr['relationship_description'],                       
                        'group': gr['group'],
                        'group_description': gr['group_description'],
                        'group_aliases': gr['group_aliases'],
                        'group_id': gr['group_id'],
                        'group_references': gr['group_references'],
                        'software_url': s['url'],
                        'software': s['software'],
                        'software_description': s['software_description'],
                        'software_labels':s['software_labels'],
                        'software_id': s['software_id'],
                        'software_aliases': s['software_aliases'],
                        'software_references': s['software_references'],
                        'software_platform': s['software_platform']
                    }
                    all_groups_software_use.append(all_groups_software)

        if group_name is None:
            return all_groups_software_use
        else:
            for gn in all_groups_software_use:
                if group_name.lower() in gn['group'].lower():
                    all_software_used.append(gn)
            return all_software_used

    def get_all_used_by_group(self, group_name=None):
        all_used = []
        if group_name is None:
            software = self.get_software_used_by_group()
            techniques = self.get_techniques_used_by_group()
            all_used = software + techniques
        else:
            software = self.get_software_used_by_group(group_name)
            techniques = self.get_techniques_used_by_group(group_name)
            all_used = software + techniques
        return all_used
    
    def get_all_data_sources(self):
        techniques = self.get_all_techniques()
        data_sources = []
        for t in techniques:
            for ds in t['data_sources'] or []:
                data_sources.append(ds.lower())
        return list(set(data_sources))

    def get_techniques_by_datasources(self, data_sources):
        techniques_results = []
        techniques = self.get_all_techniques()
        if isinstance(data_sources, list):
            for d in [x.lower() for x in data_sources]:
                for t in techniques:
                    if t['data_sources'] is not None and d in [x.lower() for x in t['data_sources']]:
                        techniques_results.append(t)
        elif isinstance(data_sources, str):
            for t in techniques:
                if t['data_sources'] is not None and data_sources.lower() in [x.lower() for x in t['data_sources']]:
                    techniques_results.append(t)
        else:
            raise Exception("Not a list or a string")
        # Remove Duplicates
        already_seen = set()
        results_dedup = []
        for d in techniques_results:
            i = str(d.items())
            if i not in already_seen:
                already_seen.add(i)
                results_dedup.append(d)
        return results_dedup