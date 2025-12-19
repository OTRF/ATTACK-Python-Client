"""Confirm technique helpers behave as expected against the fixture."""

from attackcti.utils.stix import as_dict


def test_get_techniques_by_data_components(attack_client):
    """Request techniques by data components and inspect detection enrichments."""
    techniques = attack_client.query.techniques.get_techniques_by_data_components("Process")
    assert techniques, "Expected at least one technique for the fixture"

    technique = as_dict(techniques[0])
    assert technique["name"] == "Sample Technique"

    strategies = technique.get("x_attackcti_detection_strategies")
    assert strategies, "Detection enrichment must attach strategies"

    analytics = strategies[0].get("x_attackcti_analytics")
    assert analytics, "Analytics should be populated"

    log_sources = analytics[0].get("x_attackcti_log_sources")
    assert log_sources, "Log sources are expected"

    data_component = log_sources[0].get("x_attackcti_data_component")
    assert data_component and data_component.get("name") == "Process Creation"


def test_get_technique_by_name_case_insensitive_and_sensitive(attack_client):
    """Verify case-sensitive and case-insensitive name queries."""
    exact_match = attack_client.query.techniques.get_technique_by_name(
        "Sample Technique",
        case=True,
        stix_format=False,
    )
    assert exact_match, "Exact name match should return the technique"

    partial_match = attack_client.query.techniques.get_technique_by_name(
        "Sample",
        case=False,
        stix_format=False,
    )
    assert partial_match, "Case-insensitive containment search should succeed"


def test_get_techniques_by_content_and_platform(attack_client):
    """Search descriptions and platforms using both helpers."""
    by_content = attack_client.query.techniques.get_techniques_by_content(content="synthetic", stix_format=False)
    assert by_content, "Content search should find the sample technique"

    by_platform_sensitive = attack_client.query.techniques.get_techniques_by_platform(name="Windows")
    assert by_platform_sensitive, "Platform filter with contains should find the technique"

    by_platform_insensitive = attack_client.query.techniques.get_techniques_by_platform(
        name="windows",
        case=False,
        stix_format=False,
    )
    assert by_platform_insensitive, "Case-insensitive platform search should still match"


def test_get_techniques_by_tactic_and_since_time(attack_client):
    """Ensure tactic and time filters are functioning."""
    by_tactic_sensitive = attack_client.query.techniques.get_techniques_by_tactic(name="execution")
    assert by_tactic_sensitive, "Tactic filter should return the technique"

    by_tactic_insensitive = attack_client.query.techniques.get_techniques_by_tactic(
        name="Execution",
        case=False,
        stix_format=False,
    )
    assert by_tactic_insensitive, "Case-insensitive tactic lookup should still succeed"

    since_time = attack_client.query.techniques.get_techniques_since_time(timestamp="2023-01-01T00:00:00.000Z")
    assert since_time, "Timestamp filter should include the sample technique"
