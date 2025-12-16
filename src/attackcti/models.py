from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, model_validator

class ExternalReference(BaseModel):
    url: Optional[str] = None
    source_name: Optional[str] = None
    external_id: Optional[str] = None

class STIXCore(BaseModel):
    type: str
    id: str
    url: Optional[str] = None
    matrix: Optional[List[str]] = Field(None, alias="x_mitre_domains")
    created: str
    modified: Optional[str] = None
    created_by_ref: Optional[str] = None
    modified_by_ref: Optional[str] = Field(None, alias='x_mitre_modified_by_ref')
    external_references: Optional[List[ExternalReference]] = None
    object_marking_refs: Optional[List[str]] = None
    mitre_version: Optional[str] = Field(None, alias='x_mitre_version')
    mitre_attack_spec_version: Optional[str] = Field(None, alias='x_mitre_attack_spec_version')
    mitre_deprecated: Optional[bool] = Field(None, alias='x_mitre_deprecated')
    
    @model_validator(mode='before')
    def extract_common_fields(cls, values):
        external_references = values.get('external_references')
        if external_references and len(external_references) > 0:
            first_ref = external_references[0]
            if 'url' in first_ref:
                values['url'] = first_ref['url']
        return values

    @classmethod
    def extract_external_id(cls, external_references: List[ExternalReference]):
        if external_references and len(external_references) > 0:
            return external_references[0].external_id
        return None

class Technique(STIXCore):
    technique: str = Field(..., alias='name')
    technique_id: Optional[str] = None
    technique_description: Optional[str] = Field(None, alias='description')
    tactic: List[str] = Field(default_factory=list, alias='kill_chain_phases')
    technique_detection: Optional[str] = Field(None, alias='x_mitre_detection')
    platform: Optional[List[str]] = Field(None, alias='x_mitre_platforms')
    data_sources: Optional[List[str]] = Field(None, alias='x_mitre_data_sources')
    defense_bypassed: Optional[List[str]] = Field(None, alias='x_mitre_defense_bypassed')
    permissions_required: Optional[List[str]] = Field(None, alias='x_mitre_permissions_required')
    effective_permissions: Optional[List[str]] = Field(None, alias='x_mitre_effective_permissions')
    system_requirements: Optional[List[str]] = Field(None, alias='x_mitre_system_requirements')
    network_requirements: Optional[bool] = Field(None, alias='x_mitre_network_requirements')
    remote_support: Optional[bool] = Field(None, alias='x_mitre_remote_support')
    contributors: Optional[List[str]] = Field(None, alias='x_mitre_contributors')
    tactic_type: Optional[List[str]] = Field(None, alias='x_mitre_tactic_type')
    impact_type: Optional[List[str]] = Field(None, alias='x_mitre_impact_type')
    is_subtechnique: Optional[bool] = Field(None, alias='x_mitre_is_subtechnique')
        
    @model_validator(mode='before')
    def extract_phase_name(cls, values: Dict[str, Any]):
        if 'kill_chain_phases' in values:
            kill_chain_phases = values['kill_chain_phases']
            phase_names = [phase['phase_name'] for phase in kill_chain_phases if 'phase_name' in phase]
            values['kill_chain_phases'] = phase_names
        return values
    
    @model_validator(mode='after')
    def set_technique_id(self):
        self.technique_id = self.extract_external_id(self.external_references)
        return self

class Mitigation(STIXCore):
    mitigation: str = Field(..., alias='name')
    mitigation_id: Optional[str] = None
    mitigation_description: Optional[str] = Field(None, alias='description')
    old_mitigation_id: Optional[str] = Field(None, alias='x_mitre_old_attack_id')
    
    @model_validator(mode='after')
    def set_mitigation_id(self):
        self.mitigation_id = self.extract_external_id(self.external_references)
        return self

class Group(STIXCore):
    group: str = Field(..., alias='name')
    group_id: Optional[str] = None
    group_description: Optional[str] = Field(None, alias='description')
    group_aliases: Optional[List[str]] = Field(None, alias='aliases')
    contributors: Optional[List[str]] = Field(None, alias='x_mitre_contributors')
    
    @model_validator(mode='after')
    def set_group_id(self):
        self.group_id = self.extract_external_id(self.external_references)
        return self

class Software(STIXCore):
    software: str = Field(..., alias='name')
    software_id: Optional[str] = None
    software_description: Optional[str] = Field(None, alias='description')
    software_labels: Optional[List[str]] = Field(None, alias='labels')
    software_aliases: Optional[List[str]] = Field(None, alias='x_mitre_aliases')
    software_platform: Optional[List[str]] = Field(None, alias='x_mitre_platforms')
    old_software_id: Optional[str] = Field(None, alias='x_mitre_old_attack_id')
    contributors: Optional[List[str]] = Field(None, alias='x_mitre_contributors')
    
    @model_validator(mode='after')
    def set_software_id(self):
        self.software_id = self.extract_external_id(self.external_references)
        return self

class DataComponent(STIXCore):
    data_component: str = Field(..., alias='name')
    data_component_description: Optional[str] = Field(None, alias='description')
    data_component_labels: Optional[List[str]] = Field(None, alias='labels')
    data_source: Optional[str] = Field(None, alias='x_mitre_data_source_ref')

class Relationship(STIXCore):
    relationship: str = Field(..., alias='relationship_type')
    source_object: str = Field(..., alias='source_ref')
    target_object: str = Field(..., alias='target_ref')
    relationship_description: Optional[str] = Field(None, alias='description')

class Tactic(STIXCore):
    tactic: str = Field(..., alias='name')
    tactic_id: Optional[str] = None
    tactic_description: Optional[str] = Field(None, alias='description')
    tactic_shortname: Optional[str] = Field(None, alias='x_mitre_shortname')
    
    @model_validator(mode='after')
    def set_tactic_id(self):
        self.tactic_id = self.extract_external_id(self.external_references)
        return self

class Matrix(STIXCore):
    matrix: str = Field(..., alias='name')
    matrix_id: Optional[str] = None
    matrix_description: Optional[str] = Field(None, alias='description')
    tactic_references: Optional[List[str]] = Field(None, alias='tactic_refs')
    
    @model_validator(mode='after')
    def set_matrix_id(self):
        self.matrix_id = self.extract_external_id(self.external_references)
        return self

class Identity(STIXCore):
    identity: str = Field(..., alias='name')
    identity_class: str

class Definition(BaseModel):
    statement: str

class MarkingDefinition(STIXCore):
    marking_definition_type: str = Field(..., alias='definition_type')
    marking_definition: Definition = Field(..., alias='definition')

class DataSource(STIXCore):
    data_source: str = Field(..., alias='name')
    data_source_description: Optional[str] = Field(None, alias='description')
    software_platform: Optional[List[str]] = Field(None, alias='x_mitre_platforms')
    collection_layers: Optional[List[str]] = Field(None, alias='x_mitre_collection_layers')
    contributors: Optional[List[str]] = Field(None, alias='x_mitre_contributors')
    data_components: Optional[List[DataComponent]] = None

class Campaign(STIXCore):
    campaign: str = Field(..., alias='name')
    campaign_id: Optional[str] = None
    campaign_description: Optional[str] = Field(None, alias='description')
    campaign_aliases: Optional[List[str]] = Field(None, alias='aliases')
    first_seen_citation: Optional[str] = Field(None, alias='x_mitre_first_seen_citation')
    last_seen_citation: Optional[str] = Field(None, alias='x_mitre_last_seen_citation')
    
    @model_validator(mode='after')
    def set_campaign_id(self):
        self.campaign_id = self.extract_external_id(self.external_references)
        return self

class GroupTechnique(Group):
    technique_ref: str
    relationship_description: str
    relationship_id: str
    technique_revoked: bool = Field(None, alias='revoked')
    technique: str
    technique_description: str
    tactic: List[str] = Field(default_factory=list)
    technique_id: str
    technique_matrix: List[str]
    platform: List[str]
    data_sources: Optional[List[str]] = None

    @model_validator(mode='before')
    def extract_phase_name(cls, values: Dict[str, Any]):
        if 'tactic' in values:
            kill_chain_phases = values['tactic']
            phase_names = [phase['phase_name'] for phase in kill_chain_phases if 'phase_name' in phase]
            values['tactic'] = phase_names
        return values

class STIXLocalPaths(BaseModel):
    enterprise: Optional[str] = Field(None, description="Path to the local enterprise-attack directory or JSON file.")
    mobile: Optional[str] = Field(None, description="Path to the local mobile-attack directory or JSON file.")
    ics: Optional[str] = Field(None, description="Path to the local ics-attack directory or JSON file.")
