"""Integration checks for Detections helpers using live ATT&CK data."""

import pytest


@pytest.mark.integration
def test_real_data_components(real_client):
    """Verify detections return data components for a live technique."""
    techniques = real_client.query.techniques.get_techniques()
    assert techniques, "Expected live techniques to exist"
    components = real_client.query.detections.get_data_components_by_technique_via_analytics(
        techniques[0].id,
        stix_format=True,
    )
    assert isinstance(components, list)
    assert components, "Real ATT&CK data should expose components via analytics"
