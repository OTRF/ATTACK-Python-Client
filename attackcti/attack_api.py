#!/usr/bin/env python

# ATTCK Client Main Script
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

    def handle_list(self, stix_objs, object_type):
        objects_list = list()
        if object_type == 'kill_chain_phases':
            for o in stix_objs[object_type]:
                objects_list.append(o.phase_name)
            return objects_list
        elif object_type == 'external_references':
            for o in stix_objs[object_type]:
                if o['source_name'] != 'mitre-attack' and o['source_name'] in stix_objs[object_type]:
                    objects_list.append(o.url)
                else:
                    return None
            return objects_list
        else:
            for o in stix_objs[object_type]:
                    objects_list.append(o)
            return objects_list

    def try_except(self, stix_objs, object_type):
        if object_type in stix_objs:
            stix_objects = stix_objs[object_type]
            if isinstance(stix_objects, list):
                lists = self.handle_list(stix_objs, object_type)
                return lists
            else:
                return stix_objs[object_type]
        else:
            return None

    def get_all_enterprise(self):
        all_stix_objects = {}
        enterprise_filter_objs = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship")
        }
        enterprise_stix_objects = {}
        for key in enterprise_filter_objs:
                enterprise_stix_objects[key] = self.TC_ENTERPRISE_SOURCE.query(enterprise_filter_objs[key])
                all_stix_objects[key] = self.parse_stix_objects(enterprise_stix_objects[key], key)
        return all_stix_objects
    
    def get_all_pre(self):
        all_stix_objects = {}
        pre_filter_objs = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "groups": Filter("type", "=", "intrusion-set"),
            "relationships": Filter("type", "=", "relationship")
        }
        pre_stix_objects = {}
        for key in pre_filter_objs:
                pre_stix_objects[key] = self.TC_PRE_SOURCE.query(pre_filter_objs[key])
                all_stix_objects[key] = self.parse_stix_objects(pre_stix_objects[key], key)           
        return all_stix_objects
    
    def get_all_mobile(self):
        all_stix_objects = {}
        mobile_filter_objs = {
            "techniques": Filter("type", "=", "attack-pattern"),
            "mitigations": Filter("type", "=", "course-of-action"),
            "groups": Filter("type", "=", "intrusion-set"),
            "malware": Filter("type", "=", "malware"),
            "tools": Filter("type", "=", "tool"),
            "relationships": Filter("type", "=", "relationship")
        }
        mobile_stix_objects = {}
        for key in mobile_filter_objs:
                mobile_stix_objects[key] = self.TC_MOBILE_SOURCE.query(mobile_filter_objs[key])
                all_stix_objects[key] = self.parse_stix_objects(mobile_stix_objects[key], key)           
        return all_stix_objects
    
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

    def get_all_enterprise_techniques(self,enterprise_objects=None):
        if enterprise_objects is None:
            enterprise_techniques = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "attack-pattern"))
            enterprise_techniques = self.parse_stix_objects(enterprise_techniques, 'techniques')
            return enterprise_techniques
        else:
            return enterprise_objects['techniques']
    
    def get_all_pre_techniques(self,pre_objects=None):
        if pre_objects is None:
            pre_techniques = self.TC_PRE_SOURCE.query(Filter("type", "=", "attack-pattern"))
            pre_techniques = self.parse_stix_objects(pre_techniques, 'techniques')
            return pre_techniques
        else:
            return pre_objects['techniques']
    
    def get_all_mobile_techniques(self,mobile_objects=None):
        if mobile_objects is None:
            mobile_techniques = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "attack-pattern"))
            mobile_techniques = self.parse_stix_objects(mobile_techniques, 'techniques')
            return mobile_techniques
        else:
            return mobile_objects['techniques']
    
    def get_all_techniques(self,all_objects=None):
        if all_objects is None:
            enterprise_techniques = self.get_all_enterprise_techniques()
            pre_techniques = self.get_all_pre_techniques()
            mobile_techniques = self.get_all_mobile_techniques()
            all_techniques = enterprise_techniques + pre_techniques + mobile_techniques
            return all_techniques
        else:
            return all_objects['techniques']
  
    def get_all_enterprise_groups(self,enterprise_objects=None):
        if enterprise_objects is None:
            enterprise_groups = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "intrusion-set"))
            enterprise_groups = self.parse_stix_objects(enterprise_groups, 'groups')
            return enterprise_groups
        else:
            return enterprise_objects['groups']
    
    def get_all_pre_groups(self,pre_objects=None):
        if pre_objects is None:
            pre_groups = self.TC_PRE_SOURCE.query(Filter("type", "=", "intrusion-set"))
            pre_groups = self.parse_stix_objects(pre_groups, 'groups')
            return pre_groups
        else:
            return pre_objects['groups']
    
    def get_all_mobile_groups(self,mobile_objects=None):
        if mobile_objects is None:
            mobile_groups = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "intrusion-set"))
            mobile_groups = self.parse_stix_objects(mobile_groups, 'groups')
            return mobile_groups
        else:
            return mobile_objects['groups']
    
    def get_all_groups(self,all_objects=None):
        if all_objects is None:
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
        else:
            return all_objects['groups']
    
    def get_all_enterprise_mitigations(self,enterprise_objects=None):
        if enterprise_objects is None:
            enterprise_mitigations = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "course-of-action"))
            enterprise_mitigations = self.parse_stix_objects(enterprise_mitigations, 'mitigations')
            return enterprise_mitigations
        else:
            return enterprise_objects['mitigations']
    
    def get_all_mobile_mitigations(self,mobile_objects=None):
        if mobile_objects is None:
            mobile_mitigations = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "course-of-action"))
            mobile_mitigations = self.parse_stix_objects(mobile_mitigations, 'mitigations')
            return mobile_mitigations
        else:
            return mobile_objects['mitigations']
    
    def get_all_mitigations(self,all_objects=None):
        if all_objects is None:
            enterprise_mitigations = self.get_all_enterprise_mitigations()
            mobile_mitigations = self.get_all_mobile_mitigations()
            for mm in mobile_mitigations:
                if mm not in enterprise_mitigations:
                    enterprise_mitigations.append(mm)
            return enterprise_mitigations
        else:
            return all_objects['mitigations']
    
    def get_all_software(self, all_objects=None):
        if all_objects is None:
            enterprise_malware = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "malware"))
            enterprise_tools = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "tool"))
            mobile_malware = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "malware"))
            mobile_tools = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "tool"))
            enterprise_malware = self.parse_stix_objects(enterprise_malware, 'malware')
            enterprise_tools = self.parse_stix_objects(enterprise_tools, 'tools')
            mobile_malware = self.parse_stix_objects(mobile_malware, 'malware')
            mobile_tools = self.parse_stix_objects(mobile_tools, 'tools')
            for mt in mobile_tools:
                if mt not in enterprise_tools:
                    enterprise_tools.append(mt)
            for mmal in mobile_malware:
                if mmal not in enterprise_malware:
                    enterprise_malware.append(mmal)
            all_software = enterprise_tools + enterprise_malware
            return all_software
        else:
            all_tools = all_objects['tools']
            all_malware = all_objects['malware']
            all_software = all_tools + all_malware
        return all_software
    
    def get_all_enterprise_relationships(self,enterprise_objects=None):
        if enterprise_objects is None:
            enterprise_relationships = self.TC_ENTERPRISE_SOURCE.query(Filter("type", "=", "relationship"))
            enterprise_relationships = self.parse_stix_objects(enterprise_relationships, 'relationships')
            return enterprise_relationships
        else:
            return enterprise_objects['relationships']
    
    def get_all_pre_relationships(self,pre_objects=None):
        if pre_objects is None:
            pre_relationships = self.TC_PRE_SOURCE.query(Filter("type", "=", "relationship"))
            pre_relationships = self.parse_stix_objects(pre_relationships, 'relationships')
            return pre_relationships
        else:
            return pre_objects['relationships']
    
    def get_all_mobile_relationships(self,mobile_objects=None):
        if mobile_objects is None:
            mobile_relationships = self.TC_MOBILE_SOURCE.query(Filter("type", "=", "relationship"))
            mobile_relationships = self.parse_stix_objects(mobile_relationships, 'relationships')
            return mobile_relationships
        else:
            return mobile_objects['relationships']
    
    def get_all_relationships(self,all_objects=None):
        if all_objects is None:
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
        else:
            return all_objects['relationships']
    
    def get_technique_by_name(self, name, all_objects=None):
        if all_objects is None:
            filter_objs = [
                Filter('type', '=', 'attack-pattern'),
                Filter('name', '=', name)
            ]
            enterprise_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objs)
            enterprise_stix_objects = self.parse_stix_objects(enterprise_objects, 'techniques')
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objs)
            pre_stix_objects = self.parse_stix_objects(pre_stix_objects, 'techniques')
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objs)
            mobile_stix_objects = self.parse_stix_objects(mobile_stix_objects, 'techniques')   
            all_stix_objects = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
            for o in all_stix_objects:
                return o
        else:
            for o in all_objects['techniques']:
                if o['technique'].lower() == name.lower():
                    return o

    def get_object_by_attack_id(self, object_type, attack_id, all_objects=None):
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
            if all_objects is None:
                filter_objs = [
                    Filter('type', '=', object_type),
                    Filter('external_references.external_id', '=', attack_id)
                ]
                enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objs)
                enterprise_stix_objects = self.parse_stix_objects(enterprise_stix_objects, dictionary[object_type])
                pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objs)
                pre_stix_objects = self.parse_stix_objects(pre_stix_objects, dictionary[object_type])
                mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objs)
                mobile_stix_objects = self.parse_stix_objects(mobile_stix_objects, dictionary[object_type])
                all_stix_objects = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
                for o in all_stix_objects:
                    return o
            else:
                if dictionary[object_type] == 'techniques':
                    object_id = 'technique id'
                elif dictionary[object_type] == 'groups':
                    object_id = 'group id'
                elif dictionary[object_type] == 'malware' or dictionary[object_type] == 'tools':
                    object_id = 'software id'
                elif dictionary[object_type] == 'mitigations':
                    object_id = 'mitigation id'
                else:
                    exit           
                for o in all_objects[dictionary[object_type]]:
                    if o[object_id] == attack_id:
                        return o

    def get_group_by_alias(self, group_alias, all_objects=None):
        if all_objects is None:
            filter_objs = [
                Filter('type', '=', 'intrusion-set'),
                Filter('aliases', '=', group_alias)
            ]
            enterprise_stix_objects = self.TC_ENTERPRISE_SOURCE.query(filter_objs)
            enterprise_stix_objects = self.parse_stix_objects(enterprise_stix_objects, 'groups')
            pre_stix_objects = self.TC_PRE_SOURCE.query(filter_objs)
            pre_stix_objects = self.parse_stix_objects(pre_stix_objects, 'groups')
            mobile_stix_objects = self.TC_MOBILE_SOURCE.query(filter_objs)
            mobile_stix_objects = self.parse_stix_objects(mobile_stix_objects, 'groups')
            all_stix_objects = enterprise_stix_objects + pre_stix_objects + mobile_stix_objects
            for o in all_stix_objects:
                return o
        else:
            for o in all_objects['groups']:
                for a in o['group aliases']:
                    if group_alias.lower() in a.lower():
                        return o
    
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
                        if g['object id'] == r['source object'] and r['relationship'] == 'uses':
                            all_groups_relationships_dict = {
                                'target object' : r['target object'],
                                'relationship description' : r['relationship description'],
                                'matrix': g['matrix'],
                                'url': g['url'],
                                'group': g['group'],
                                'group description': g['group description'],
                                'group aliases': g['group aliases'],
                                'group id': g['group id'],
                                'group references': g['group references']
                            }
                            all_relationships.append(all_groups_relationships_dict)
            elif stix_object.lower() == 'software':
                software = self.get_all_software()
                relationships = self.get_all_relationships()
                for s in software:
                    for r in relationships:
                        if s['object id'] == r['source object'] and r['relationship'] == 'uses':
                            all_software_relationships_dict = {
                                'target object' : r['target object'],
                                'relationship description' : r['relationship description'],
                                'software type': s['object type'],
                                'matrix': s['matrix'],
                                'software': s['software'],
                                'software description': s['software description'],
                                'software labels':s['software labels'],
                                'software id': s['software id'],
                                'url': s['url'],
                                'software aliases': s['software aliases'],
                                'software references': s['software references']
                            }
                            all_relationships.append(all_software_relationships_dict)
            else:
                mitigations = self.get_all_mitigations()
                relationships = self.get_all_relationships()
                for m in mitigations:
                    for r in relationships:
                        if m['object id'] == r['source object'] and r['relationship'] == 'mitigates':
                            all_software_relationships_dict = {
                                'target object' : r['target object'],
                                'matrix': m['matrix'],
                                'mitigation': m['mitigation'],
                                'mitigation description': m['mitigation description'],
                                'mitigation id': m['mitigation id'],
                                'mitigation references': m['mitigation references']
                            }
                            all_relationships.append(all_software_relationships_dict)
            return all_relationships
    
    def get_all_techniques_with_mitigations(self):
        all_mitigations_mitigate = []
        technique_ids = []
        all_mitigations_relationships = self.get_relationships_by_object('mitigations')
        techniques = self.get_all_techniques()
        for mr in all_mitigations_relationships:
            for t in techniques:
                if t['object id'] == mr['target object']:
                    all_mitigations_dict = {
                        'matrix': t['matrix'],
                        'mitigation': mr['mitigation'],
                        'mitigation description': mr['mitigation description'],
                        'mitigation id' :mr['mitigation id'],
                        'mitigation references': mr['mitigation references'],
                        'technique' : t['technique'],
                        'technique description' : t['technique description'],
                        'tactic' : t['tactic'],
                        'url' : t['url'],
                        'technique id' : t['technique id'],
                        'platforms' : t['platforms'],
                        'data sources' : t['data sources'],
                        'defense bypassed' : t['defense bypassed'],
                        'permission required' : t['permission required'],
                        'effective permissions' : t['effective permissions'],
                        'system requirements' : t['system requirements'],
                        'network requirements' : t['network requirements'],
                        'remote support' : t['remote support'],
                        'contributors' : t['contributors'],
                        'technique references' : t['technique references'],
                        'detectable' : t['detectable'],
                        'detectable description' : t['detectable description'],
                        'difficulty' : t['difficulty'],
                        'difficulty description': t['difficulty description'],
                        'tactic type' : t['tactic type']
                    }
                    all_mitigations_mitigate.append(all_mitigations_dict)
                    technique_ids.append(t['technique id'])
        for t in techniques:
            if t['technique id'] not in technique_ids:
                all_techniques_dict = {
                    'matrix': t['matrix'],
                    'technique' : t['technique'],
                    'technique description' : t['technique description'],
                    'tactic' : t['tactic'],
                    'url' : t['url'],
                    'technique id' : t['technique id'],
                    'platforms' : t['platforms'],
                    'data sources' : t['data sources'],
                    'defense bypassed' : t['defense bypassed'],
                    'permission required' : t['permission required'],
                    'effective permissions' : t['effective permissions'],
                    'system requirements' : t['system requirements'],
                    'network requirements' : t['network requirements'],
                    'remote support' : t['remote support'],
                    'contributors' : t['contributors'],
                    'technique references' : t['technique references'],
                    'detectable' : t['detectable'],
                    'detectable description' : t['detectable description'],
                    'difficulty' : t['difficulty'],
                    'difficulty description': t['difficulty description'],
                    'tactic type' : t['tactic type']
                }
                all_mitigations_mitigate.append(all_techniques_dict)
        return all_mitigations_mitigate
    
    def get_all_data_sources(self):
        techniques = self.get_all_techniques()
        data_sources = []
        for t in techniques:
            for ds in t['data sources'] or []:
                data_sources.append(ds.lower())
        return list(set(data_sources))

    def get_techniques_used_by_software(self, software_name=None):
        all_software_use = []
        all_techniques_used = []
        all_software_relationships = self.get_relationships_by_object('software')
        techniques = self.get_all_techniques()
        for sr in all_software_relationships:
            for t in techniques:
                if t['object id'] == sr['target object']:
                    all_groups_use_dict = {
                        'matrix': t['matrix'],
                        'relationship description': sr['relationship description'],
                        'software': sr['software'],
                        'software description': sr['software description'],
                        'software labels':sr['software labels'],
                        'software id': sr['software id'],
                        'software aliases': sr['software aliases'],
                        'software references': sr['software references'],
                        'technique' : t['technique'],
                        'technique description' : t['technique description'],
                        'tactic' : t['tactic'],
                        'technique id' : t['technique id'],
                        'url' : t['url'],
                        'platforms' : t['platforms'],
                        'data sources' : t['data sources'],
                        'defense bypassed' : t['defense bypassed'],
                        'permission required' : t['permission required'],
                        'effective permissions' : t['effective permissions'],
                        'system requirements' : t['system requirements'],
                        'network requirements' : t['network requirements'],
                        'remote support' : t['remote support'],
                        'contributors' : t['contributors'],
                        'technique references' : t['technique references'],
                        'detectable' : t['detectable'],
                        'detectable description' : t['detectable description'],
                        'difficulty' : t['difficulty'],
                        'difficulty description': t['difficulty description'],
                        'tactic type' : t['tactic type']
                    }
                    all_software_use.append(all_groups_use_dict)
        if software_name is None:
            return all_software_use
        else:
            for sn in all_software_use:
                if software_name.lower() in sn['software'].lower():
                    all_techniques_used.append(sn)
            return all_techniques_used
    
    def get_techniques_used_by_group(self, group_name=None):
        all_groups_use = []
        all_techniques_used = []
        all_groups_relationships = self.get_relationships_by_object('groups')
        techniques = self.get_all_techniques()
        for gr in all_groups_relationships:
            for t in techniques:
                if t['object id'] == gr['target object']:
                    all_groups_use_dict = {
                        'matrix': t['matrix'],
                        'relationship description': gr['relationship description'],
                        'group': gr['group'],
                        'group description': gr['group description'],
                        'group aliases': gr['group aliases'],
                        'group id': gr['group id'],
                        'group references': gr['group references'],
                        'technique' : t['technique'],
                        'technique description' : t['technique description'],
                        'tactic' : t['tactic'],
                        'technique id' : t['technique id'],
                        'url' : t['url'],
                        'platforms' : t['platforms'],
                        'data sources' : t['data sources'],
                        'defense bypassed' : t['defense bypassed'],
                        'permission required' : t['permission required'],
                        'effective permissions' : t['effective permissions'],
                        'system requirements' : t['system requirements'],
                        'network requirements' : t['network requirements'],
                        'remote support' : t['remote support'],
                        'contributors' : t['contributors'],
                        'technique references' : t['technique references'],
                        'detectable' : t['detectable'],
                        'detectable description' : t['detectable description'],
                        'difficulty' : t['difficulty'],
                        'difficulty description': t['difficulty description'],
                        'tactic type' : t['tactic type']
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
        all_groups_use = []
        all_software_used = []
        all_groups_relationships = self.get_relationships_by_object('groups')
        software = self.get_all_software()
        for gr in all_groups_relationships:
            for s in software:
                if s['object id'] == gr['target object']:
                    all_groups_use_dict = {
                        'matrix': s['matrix'],
                        'relationship description': gr['relationship description'],                       
                        'group': gr['group'],
                        'group description': gr['group description'],
                        'group aliases': gr['group aliases'],
                        'group id': gr['group id'],
                        'group references': gr['group references'],
                        'software url': s['url'],
                        'software': s['software'],
                        'software description': s['software description'],
                        'software labels':s['software labels'],
                        'software id': s['software id'],
                        'software aliases': s['software aliases'],
                        'software references': s['software references']
                    }
                    all_groups_use.append(all_groups_use_dict)
        if group_name is None:
            return all_groups_use
        else:
            for gn in all_groups_use:
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
    
    def get_all_attack(self):       
        techniques = self.get_all_techniques_with_mitigations()
        software = self.get_all_software()
        software_techniques = self.get_techniques_used_by_software()
        groups = self.get_all_groups()
        groups_use = self.get_all_used_by_group()
        for s in software:
            del s['object type'],s['object id'],s['object created by ref'],s['object created'],s['object modified']
        for g in groups:
            del g['object type'],g['object id'],g['object created by ref'],g['object created'],g['object modified']
        all_attack = techniques + software + software_techniques + groups + groups_use
        return all_attack
    
    def parse_stix_objects(self, stix_objects, stix_object_type):
        stix_objects_list = list()
        if stix_object_type == 'techniques':
            for technique in stix_objects:
                technique_dict = {
                    'object type': technique['type'],
                    'object id': technique['id'],
                    'object created by ref': technique['created_by_ref'],
                    'object created': technique['created'],
                    'object modified': technique['modified'],
                    'object marking refs': technique['object_marking_refs'],
                    'url': technique['external_references'][0]['url'],
                    'matrix': technique['external_references'][0]['source_name'],
                    'technique': technique['name'],
                    'technique description': technique['description'],
                    'tactic': self.handle_list(technique,'kill_chain_phases'),
                    'technique id': technique['external_references'][0]['external_id'],
                    'platforms': self.try_except(technique,'x_mitre_platforms'),
                    'data sources': self.try_except(technique,'x_mitre_data_sources'),
                    'defense bypassed': self.try_except(technique,'x_mitre_defense_bypassed'),
                    'permission required': self.try_except(technique,'x_mitre_permissions_required'),
                    'effective permissions': self.try_except(technique,'x_mitre_effective_permissions'),
                    'system requirements': self.try_except(technique,'x_mitre_system_requirements'),
                    'network requirements': self.try_except(technique,'x_mitre_network_requirements'),
                    'remote support': self.try_except(technique,'x_mitre_remote_support'),
                    'contributors': self.try_except(technique,'x_mitre_contributors'),
                    'technique references': self.try_except(technique,'external_references'),
                    'detectable': self.try_except(technique,'x_mitre_detectable_by_common_defenses'),
                    'detectable description': self.try_except(technique,'x_mitre_detectable_by_common_defenses_explanation'),
                    'difficulty': self.try_except(technique,'x_mitre_difficulty_for_adversary'),
                    'difficulty description': self.try_except(technique,'x_mitre_difficulty_for_adversary_explanation'),
                    'tactic type': self.try_except(technique,'x_mitre_tactic_type')
                }
                stix_objects_list.append(technique_dict)
        elif stix_object_type == "mitigations":
            for mitigation in stix_objects:
                mitigation_dict = {
                    'object type': mitigation['type'],
                    'object id': mitigation['id'],
                    'object created by ref': mitigation['created_by_ref'],
                    'object created': mitigation['created'],
                    'object modified': mitigation['modified'],
                    'matrix': mitigation['external_references'][0]['source_name'],
                    'url': mitigation['external_references'][0]['url'],
                    'mitigation': mitigation['name'],
                    'mitigation description': mitigation['description'],
                    'mitigation id': mitigation['external_references'][0]['external_id'],
                    'mitigation references': self.handle_list(mitigation,'external_references')
                }
                stix_objects_list.append(mitigation_dict)
        elif stix_object_type == "groups":
            for group in stix_objects:
                group_dict = {
                    'object type': group['type'],
                    'object id': group['id'],
                    'object created by ref': self.try_except(group, 'created_by_ref'),
                    'matrix': group['external_references'][0]['source_name'],
                    'object created': group['created'],
                    'object modified': group['modified'],
                    'url': group['external_references'][0]['url'],
                    'group': group['name'],
                    'group description': self.try_except(group, 'description'),
                    'group aliases': self.try_except(group, 'aliases'),
                    'group id': group['external_references'][0]['external_id'],
                    'group references': self.try_except(group,'external_references')
                }
                stix_objects_list.append(group_dict)
        elif stix_object_type == "tools" or stix_object_type == "malware":
             for software in stix_objects:
                software_dict = {
                    'object type': software['type'],
                    'object id': software['id'],
                    'object created by ref': software['created_by_ref'],
                    'object created': software['created'],
                    'object modified': software['modified'],
                    'matrix': software['external_references'][0]['source_name'],
                    'software': software['name'],
                    'software description': software['description'],
                    'software labels': self.try_except(software, 'labels'),
                    'software id': software['external_references'][0]['external_id'],
                    'url': software['external_references'][0]['url'],
                    'software aliases': self.try_except(software, 'x_mitre_aliases'),
                    'software references': self.try_except(software,'external_references')
                }
                stix_objects_list.append(software_dict)
        elif stix_object_type == "relationships":
            for relationship in stix_objects:
                relationship_dict = {
                    'object type': relationship['type'],
                    'object id': relationship['id'],
                    'object created by ref': relationship['created_by_ref'],
                    'object created': relationship['created'],
                    'object modified': relationship['modified'],
                    'relationship': relationship['relationship_type'],
                    'relationship description': self.try_except(relationship, 'description'),
                    'source object': relationship['source_ref'],
                    'target object': relationship['target_ref']
                }
                stix_objects_list.append(relationship_dict)
        else:
            exit

        return stix_objects_list