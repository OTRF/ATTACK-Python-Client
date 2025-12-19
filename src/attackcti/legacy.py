"""Attach legacy `MitreAttackClient.get_*` methods.

The modern API is exposed via sub-clients (composition), e.g.:
- `client.enterprise.get_techniques()`
- `client.relationships.get_software_used_by_group()`

For backwards compatibility, this module installs `MitreAttackClient.get_*` methods which delegate to
the appropriate sub-client methods.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Tuple

LegacyTarget = Tuple[str, str]


LEGACY_METHODS: Dict[str, LegacyTarget] = {
    # Query (cross-domain)
    "get_attack": ("query", "get_attack"),
    "get_campaigns": ("query.campaigns", "get_campaigns"),
    "get_techniques": ("query.techniques", "get_techniques"),
    "get_groups": ("query.groups", "get_groups"),
    "get_mitigations": ("query.mitigations", "get_mitigations"),
    "get_data_components": ("query.data_sources", "get_data_components"),
    "get_software": ("query.software", "get_software"),
    "get_relationships": ("query.relationships", "get_relationships"),
    "get_tactics": ("query.tactics", "get_tactics"),
    "get_data_sources": ("query.data_sources", "get_data_sources"),
    "get_technique_by_name": ("query.techniques", "get_technique_by_name"),
    "get_techniques_by_content": ("query.techniques", "get_techniques_by_content"),
    "get_techniques_by_platform": ("query.techniques", "get_techniques_by_platform"),
    "get_techniques_by_tactic": ("query.techniques", "get_techniques_by_tactic"),
    "get_object_by_attack_id": ("query", "get_object_by_attack_id"),
    "get_campaign_by_alias": ("query.campaigns", "get_campaign_by_alias"),
    "get_group_by_alias": ("query.groups", "get_group_by_alias"),
    "get_campaigns_since_time": ("query.campaigns", "get_campaigns_since_time"),
    "get_techniques_since_time": ("query.techniques", "get_techniques_since_time"),
    # Enterprise domain
    "get_enterprise": ("enterprise", "get"),
    "get_enterprise_campaigns": ("enterprise", "get_campaigns"),
    "get_enterprise_techniques": ("enterprise", "get_techniques"),
    "get_enterprise_data_components": ("enterprise", "get_data_components"),
    "get_enterprise_mitigations": ("enterprise", "get_mitigations"),
    "get_enterprise_groups": ("enterprise", "get_groups"),
    "get_enterprise_malware": ("enterprise", "get_malware"),
    "get_enterprise_tools": ("enterprise", "get_tools"),
    "get_enterprise_relationships": ("enterprise", "get_relationships"),
    "get_enterprise_tactics": ("enterprise", "get_tactics"),
    "get_enterprise_data_sources": ("enterprise", "get_data_sources"),
    # Mobile domain
    "get_mobile": ("mobile", "get"),
    "get_mobile_campaigns": ("mobile", "get_campaigns"),
    "get_mobile_techniques": ("mobile", "get_techniques"),
    "get_mobile_data_components": ("mobile", "get_data_components"),
    "get_mobile_mitigations": ("mobile", "get_mitigations"),
    "get_mobile_groups": ("mobile", "get_groups"),
    "get_mobile_malware": ("mobile", "get_malware"),
    "get_mobile_tools": ("mobile", "get_tools"),
    "get_mobile_relationships": ("mobile", "get_relationships"),
    "get_mobile_tactics": ("mobile", "get_tactics"),
    "get_mobile_data_sources": ("mobile", "get_data_sources"),
    # ICS domain
    "get_ics": ("ics", "get"),
    "get_ics_campaigns": ("ics", "get_campaigns"),
    "get_ics_techniques": ("ics", "get_techniques"),
    "get_ics_data_components": ("ics", "get_data_components"),
    "get_ics_mitigations": ("ics", "get_mitigations"),
    "get_ics_groups": ("ics", "get_groups"),
    "get_ics_malware": ("ics", "get_malware"),
    "get_ics_tools": ("ics", "get_tools"),
    "get_ics_relationships": ("ics", "get_relationships"),
    "get_ics_tactics": ("ics", "get_tactics"),
    "get_ics_data_sources": ("ics", "get_data_sources"),
    # Detections
    "get_detection_strategies": ("query.detections", "get_detection_strategies"),
    "get_analytics": ("query.detections", "get_analytics"),
    "get_detection_strategies_by_technique": ("query.detections", "get_detection_strategies_by_technique"),
    "get_analytics_by_technique": ("query.detections", "get_analytics_by_technique"),
    "get_log_source_references_by_technique": ("query.detections", "get_log_source_references_by_technique"),
    "get_data_components_by_technique_via_analytics": ("query.detections", "get_data_components_by_technique_via_analytics"),
    # Relationships
    "get_relationships_by_object": ("query.relationships", "get_relationships_by_object"),
    "get_techniques_by_relationship": ("query.relationships", "get_techniques_by_relationship"),
    "get_techniques_used_by_group": ("query.relationships", "get_techniques_used_by_group"),
    "get_techniques_used_by_all_groups": ("query.relationships", "get_techniques_used_by_all_groups"),
    "get_software_used_by_group": ("query.relationships", "get_software_used_by_group"),
    "get_techniques_used_by_software": ("query.relationships", "get_techniques_used_by_software"),
    "get_techniques_used_by_group_software": ("query.relationships", "get_techniques_used_by_group_software"),
    "get_techniques_mitigated_by_mitigations": ("query.relationships", "get_techniques_mitigated_by_mitigations"),
    "get_data_components_by_technique": ("query.detections", "get_data_components_by_technique_via_analytics"),
    "export_groups_navigator_layers": ("query.relationships", "export_groups_navigator_layers"),
}


def _make_delegator(property_name: str, method_name: str, legacy_name: str) -> Callable[..., Any]:
    def delegator(self: Any, *args: Any, **kwargs: Any) -> Any:
        target = self
        for attr in property_name.split("."):
            target = getattr(target, attr)
        method = getattr(target, method_name)
        return method(*args, **kwargs)

    delegator.__name__ = legacy_name
    delegator.__qualname__ = legacy_name
    delegator.__doc__ = f"Legacy alias for `{property_name}.{method_name}()`."
    return delegator


def attach_legacy_methods(client_cls: type) -> None:
    """Attach legacy methods to the given MitreAttackClient class."""
    for legacy_name, (property_name, method_name) in LEGACY_METHODS.items():
        if hasattr(client_cls, legacy_name):
            continue
        setattr(client_cls, legacy_name, _make_delegator(property_name, method_name, legacy_name))
