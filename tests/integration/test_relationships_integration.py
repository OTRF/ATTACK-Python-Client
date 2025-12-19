"""Integration checks for Relationships helpers against live ATT&CK data."""

import pytest


@pytest.mark.integration
def test_export_real_layers(real_client, tmp_path):
    """Ensure navigator layers can be generated from real data."""
    real_client.query.relationships.export_groups_navigator_layers(output_dir=str(tmp_path))
    generated = list(tmp_path.glob("*.json"))
    assert generated, "Should export at least one navigator layer from real data"


@pytest.mark.integration
def test_real_uses_relationships(real_client):
    """Verify real group → technique uses relationships exist."""
    groups = real_client.query.groups.get_groups()
    assert groups, "Live feed should expose intrusion-set groups"
    techniques = real_client.query.relationships.get_techniques_used_by_group(groups[0])
    assert techniques, "Group should map to techniques"
