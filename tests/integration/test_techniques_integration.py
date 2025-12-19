"""Integration checks for Techniques helpers running on live ATT&CK data."""

import pytest


@pytest.mark.integration
def test_real_technique_detection_walk(real_client):
    """Walk real detection data components via the Techniques client."""
    techniques = real_client.query.techniques.get_techniques_by_data_components("Process")
    assert techniques, "Expected production data to include Process components"
    names = {tech.name for tech in techniques if hasattr(tech, "name")}
    assert any("Process" in n for n in names)


@pytest.mark.integration
def test_real_techniques_since_time(real_client):
    """Ensure time-based queries return recent techniques."""
    recent = real_client.query.techniques.get_techniques_since_time(timestamp="2022-01-01T00:00:00.000Z")
    assert recent, "Recent techniques should be present"
