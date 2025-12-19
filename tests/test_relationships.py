"""Verify relationship helpers with the tiny fixture bundle."""

import json

from attackcti.utils.stix import as_dict


def test_get_techniques_used_by_all_groups(attack_client):
    """Ensure the group → technique lookup returns an enriched record."""
    results = attack_client.query.relationships.get_techniques_used_by_all_groups(stix_format=False)
    assert results, "Expected at least one group-technique usage record"

    sample = results[0]
    assert sample["technique_id"] == "T0001"
    assert sample["technique"] == "Sample Technique"
    assert sample["technique_revoked"] is False


def test_export_groups_navigator_layers(tmp_path, attack_client):
    """Export navigator layers for the fixture and validate the JSON."""
    attack_client.query.relationships.export_groups_navigator_layers(output_dir=str(tmp_path))
    exports = list(tmp_path.glob("*.json"))
    assert exports, "Navigator layers must be created"

    payload = json.loads(exports[0].read_text())
    techniques = payload.get("techniques") or []
    assert techniques[0]["techniqueID"] == "T0001"
    assert techniques[0]["techniqueName"] == "Sample Technique"


def test_get_techniques_used_by_group_returns_sample(attack_client):
    """Call the helper with the sample group and expect the technique."""
    groups = attack_client.query.groups.get_groups()
    assert groups, "Fixture should expose at least one group"
    sample_group = groups[0]

    techniques = attack_client.query.relationships.get_techniques_used_by_group(sample_group, stix_format=False)
    assert techniques, "Expected the sample group to use the sample technique"
    technique = techniques[0]
    assert technique["external_references"][0]["external_id"] == "T0001"


def test_get_techniques_mitigated_by_mitigations_returns_sample(attack_client):
    """Ensure the mitigation helper finds the technique referenced by the fixture."""
    mitigations = attack_client.query.mitigations.get_mitigations()
    assert mitigations, "Fixture must contain a mitigation"

    results = attack_client.query.relationships.get_techniques_mitigated_by_mitigations(
        mitigations[0],
        stix_format=False,
    )
    assert results, "Mitigation should reference the sample technique"
    assert results[0]["external_references"][0]["external_id"] == "T0001"


def test_get_techniques_used_by_software(attack_client):
    """Verify the software usage helper can trace back to the sample technique."""
    software = attack_client.query.software.get_software()
    assert software, "Fixture should include at least one software object"

    techniques = attack_client.query.relationships.get_techniques_used_by_software(
        software[0],
        stix_format=False,
    )
    assert techniques, "Sample software should exercise the sample technique"
    technique = as_dict(techniques[0])
    assert technique["id"].startswith("attack-pattern--")
