"""Exercise detection helpers and data-component lookups."""

from attackcti.utils.stix import as_dict


def test_get_data_components_by_technique_via_analytics(attack_client):
    """Ensures data components can be returned for a technique via analytics."""
    techniques = attack_client.query.techniques.get_techniques(enrich_detections=True, stix_format=True)
    assert techniques, "Fixture should expose a technique"
    technique = techniques[0]

    components = attack_client.query.detections.get_data_components_by_technique_via_analytics(
        technique.id,
        stix_format=True,
    )
    assert components, "Data components must be linked to the technique"

    names = {comp.get("name") for comp in components}
    assert "Process Creation" in names

    component_dict = as_dict(components[0])
    assert component_dict.get("id", "").startswith("x-mitre-data-component--")
