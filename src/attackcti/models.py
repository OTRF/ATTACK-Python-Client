"""Pydantic models for ATT&CK STIX objects."""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator


@dataclass(frozen=True)
class LoadedStix:
    """Container for parsed STIX objects and detected spec version."""

    spec_version: str | None
    objects: list[Any]

class LogSourceReference(BaseModel):
    """A log source reference used by an analytic."""

    x_mitre_data_component_ref: str
    name: str
    channel: str


class MutableElement(BaseModel):
    """Environment-specific analytic tuning knobs."""

    field: str
    description: str


class ExternalReference(BaseModel):
    """STIX external reference entry."""

    url: Optional[str] = None
    source_name: Optional[str] = None
    external_id: Optional[str] = None

class STIXCore(BaseModel):
    """Common fields shared across ATT&CK STIX objects."""

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
        """Extract common fields from the input dictionary.

        This method processes the input dictionary to extract and set common fields,
        such as the URL from the first external reference, if available.

        Parameters
        ----------
        values : dict
            The input dictionary containing STIX object data.

        Returns
        -------
        dict
            The updated dictionary with extracted common fields.
        """
        external_references = values.get('external_references')
        if external_references and len(external_references) > 0:
            first_ref = external_references[0]
            if 'url' in first_ref:
                values['url'] = first_ref['url']
        return values

    @classmethod
    def extract_external_id(cls, external_references: List[ExternalReference]):
        """Extract the external ID from the first external reference.

        Parameters
        ----------
        external_references : List[ExternalReference]
            A list of external references associated with the STIX object.

        Returns
        -------
        str or None
            The external ID from the first external reference, or None if not available.
        """
        if external_references and len(external_references) > 0:
            return external_references[0].external_id
        return None

class Technique(STIXCore):
    """ATT&CK Technique (Attack Pattern) model."""

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
        """Extract phase names from the technique field.

        Parameters
        ----------
        values : Dict[str, Any]
            The input dictionary containing technique data.

        Returns
        -------
        Dict[str, Any]
            The updated dictionary with extracted phase names.
        """
        if 'kill_chain_phases' in values:
            kill_chain_phases = values['kill_chain_phases']
            phase_names = [phase['phase_name'] for phase in kill_chain_phases if 'phase_name' in phase]
            values['kill_chain_phases'] = phase_names
        return values
    
    @model_validator(mode='after')
    def set_technique_id(self):
        """Set the technique ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `technique_id` attribute.
        """
        self.technique_id = self.extract_external_id(self.external_references)
        return self

class Mitigation(STIXCore):
    """ATT&CK Mitigation (Course of Action) model."""

    mitigation: str = Field(..., alias='name')
    mitigation_id: Optional[str] = None
    mitigation_description: Optional[str] = Field(None, alias='description')
    old_mitigation_id: Optional[str] = Field(None, alias='x_mitre_old_attack_id')
    
    @model_validator(mode='after')
    def set_mitigation_id(self):
        """Set the mitigation ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `mitigation_id` attribute.
        """
        self.mitigation_id = self.extract_external_id(self.external_references)
        return self

class Group(STIXCore):
    """ATT&CK Group (Intrusion Set) model."""

    group: str = Field(..., alias='name')
    group_id: Optional[str] = None
    group_description: Optional[str] = Field(None, alias='description')
    group_aliases: Optional[List[str]] = Field(None, alias='aliases')
    contributors: Optional[List[str]] = Field(None, alias='x_mitre_contributors')
    
    @model_validator(mode='after')
    def set_group_id(self):
        """Set the group ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `group_id` attribute.
        """
        self.group_id = self.extract_external_id(self.external_references)
        return self

class Software(STIXCore):
    """ATT&CK Software (Tool or Malware) model."""

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
        """Set the software ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `software_id` attribute.
        """
        self.software_id = self.extract_external_id(self.external_references)
        return self

class DataComponent(STIXCore):
    """ATT&CK Data Component model."""

    data_component: str = Field(..., alias='name')
    data_component_description: Optional[str] = Field(None, alias='description')
    data_component_labels: Optional[List[str]] = Field(None, alias='labels')
    data_source: Optional[str] = Field(None, alias='x_mitre_data_source_ref')

class Relationship(STIXCore):
    """STIX relationship model."""

    relationship: str = Field(..., alias='relationship_type')
    source_object: str = Field(..., alias='source_ref')
    target_object: str = Field(..., alias='target_ref')
    relationship_description: Optional[str] = Field(None, alias='description')

class Tactic(STIXCore):
    """ATT&CK Tactic model."""

    tactic: str = Field(..., alias='name')
    tactic_id: Optional[str] = None
    tactic_description: Optional[str] = Field(None, alias='description')
    tactic_shortname: Optional[str] = Field(None, alias='x_mitre_shortname')
    
    @model_validator(mode='after')
    def set_tactic_id(self):
        """Set the tactic ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `tactic_id` attribute.
        """
        self.tactic_id = self.extract_external_id(self.external_references)
        return self

class Matrix(STIXCore):
    """ATT&CK Matrix model."""

    matrix: str = Field(..., alias='name')
    matrix_id: Optional[str] = None
    matrix_description: Optional[str] = Field(None, alias='description')
    tactic_references: Optional[List[str]] = Field(None, alias='tactic_refs')
    
    @model_validator(mode='after')
    def set_matrix_id(self):
        """Set the matrix ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `matrix_id` attribute.
        """
        self.matrix_id = self.extract_external_id(self.external_references)
        return self

class Identity(STIXCore):
    """STIX identity model."""

    identity: str = Field(..., alias='name')
    identity_class: str

class Definition(BaseModel):
    """Marking-definition body."""

    statement: str

class MarkingDefinition(STIXCore):
    """STIX marking-definition model."""

    marking_definition_type: str = Field(..., alias='definition_type')
    marking_definition: Definition = Field(..., alias='definition')

class DataSource(STIXCore):
    """ATT&CK Data Source model."""

    data_source: str = Field(..., alias='name')
    data_source_description: Optional[str] = Field(None, alias='description')
    software_platform: Optional[List[str]] = Field(None, alias='x_mitre_platforms')
    collection_layers: Optional[List[str]] = Field(None, alias='x_mitre_collection_layers')
    contributors: Optional[List[str]] = Field(None, alias='x_mitre_contributors')
    data_components: Optional[List[DataComponent]] = None

class Campaign(STIXCore):
    """ATT&CK Campaign model."""

    campaign: str = Field(..., alias='name')
    campaign_id: Optional[str] = None
    campaign_description: Optional[str] = Field(None, alias='description')
    campaign_aliases: Optional[List[str]] = Field(None, alias='aliases')
    first_seen_citation: Optional[str] = Field(None, alias='x_mitre_first_seen_citation')
    last_seen_citation: Optional[str] = Field(None, alias='x_mitre_last_seen_citation')
    
    @model_validator(mode='after')
    def set_campaign_id(self):
        """Set the campaign ID based on the external references.

        This method extracts the external ID from the first external reference
        and assigns it to the `campaign_id` attribute.
        """
        self.campaign_id = self.extract_external_id(self.external_references)
        return self

class GroupTechnique(Group):
    """Convenience model describing group-technique usage details."""

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
        """Extract phase names from the group field.

        Parameters
        ----------
        values : Dict[str, Any]
            The input dictionary containing group data.

        Returns
        -------
        Dict[str, Any]
            The updated dictionary with extracted phase names.
        """
        if 'tactic' in values:
            kill_chain_phases = values['tactic']
            phase_names = [phase['phase_name'] for phase in kill_chain_phases if 'phase_name' in phase]
            values['tactic'] = phase_names
        return values

class STIXLocalPaths(BaseModel):
    """Paths to local STIX data for each domain."""

    enterprise: Optional[str] = Field(None, description="Path to the local enterprise-attack directory or JSON file.")
    mobile: Optional[str] = Field(None, description="Path to the local mobile-attack directory or JSON file.")
    ics: Optional[str] = Field(None, description="Path to the local ics-attack directory or JSON file.")


class DetectionStrategy(STIXCore):
    """ATT&CK Detection Strategy model (x-mitre-detection-strategy)."""

    detection_strategy: str = Field(..., alias="name")
    analytic_refs: List[str] = Field(default_factory=list, alias="x_mitre_analytic_refs")


class Analytic(STIXCore):
    """ATT&CK Analytic model (x-mitre-analytic)."""

    analytic: str = Field(..., alias="name")
    analytic_description: Optional[str] = Field(None, alias="description")
    platforms: Optional[List[str]] = Field(None, alias="x_mitre_platforms")
    log_source_references: Optional[List[LogSourceReference]] = Field(
        None, alias="x_mitre_log_source_references"
    )
    mutable_elements: Optional[List[MutableElement]] = Field(None, alias="x_mitre_mutable_elements")

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
    "x-mitre-data-component": DataComponent,
    "x-mitre-detection-strategy": DetectionStrategy,
    "x-mitre-analytic": Analytic,
}
