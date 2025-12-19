"""Cover analytics, campaigns, data sources, groups, software, and tactic helpers."""

import pytest


def test_analytics_helpers(attack_client):
    """Analytics client should return the fixture analytic and allow lookups by id."""
    analytics = attack_client.query.analytics.get_analytics()
    assert analytics, "Analytics helper should surface data from the fixture"

    analytic_id = analytics[0]["id"]
    analytics_by_id = attack_client.query.analytics.get_analytics_by_ids([analytic_id])
    assert analytic_id in analytics_by_id
    entry = analytics_by_id[analytic_id]
    assert entry["name"] == "Sample Analytic"
    assert entry.get("x_attackcti_log_sources"), "Enriched log sources should be present"


def test_campaign_helpers(attack_client):
    """Campaign helpers should filter by alias and timestamp."""
    campaigns = attack_client.query.campaigns.get_campaigns()
    assert campaigns, "Fixture must include a campaign"

    alias_match = attack_client.query.campaigns.get_campaign_by_alias(alias="Sample Campaign Alias", case=True, stix_format=False)
    assert alias_match, "Case-insensitive alias search should find the campaign"

    since_time = attack_client.query.campaigns.get_campaigns_since_time(timestamp="2023-01-01T00:00:00.000Z")
    assert since_time, "Campaign should appear in since-time results"


def test_data_source_helpers(attack_client):
    """Data source helpers should return components and emit the deprecation warning."""
    components = attack_client.query.data_sources.get_data_components()
    assert components, "Fixture provides data components"

    first_id = components[0]["id"]
    selected = attack_client.query.data_sources.get_data_components_by_ids([first_id], stix_format=False)
    assert selected and selected[0]["id"] == first_id

    with pytest.warns(DeprecationWarning):
        sources = attack_client.query.data_sources.get_data_sources(stix_format=True)
    assert sources, "Deprecated data sources should still be retrievable"
    assert isinstance(sources[0], dict)


def test_group_helpers(attack_client):
    """Group helpers should respect alias lookups."""
    groups = attack_client.query.groups.get_groups()
    assert groups, "Fixture exposes at least one group"

    alias_match = attack_client.query.groups.get_group_by_alias("Sample Group Alias", case=True)
    assert alias_match, "Alias search should resolve the group"
    assert alias_match[0].name == "Sample Group"


def test_software_helpers(attack_client):
    """Software helper should return malware and tool entries."""
    software_all = attack_client.query.software.get_software()
    assert software_all, "Fixture should expose malware/tool objects"

    malware = attack_client.query.software.get_malware()
    assert malware and malware[0]["type"] == "malware"

    tools = attack_client.query.software.get_tools()
    assert tools and tools[0]["type"] == "tool"


def test_tactics_helper(attack_client):
    """Ensure tactics client can return fixture tactics."""
    tactics = attack_client.query.tactics.get_tactics()
    assert tactics, "Fixture contains at least one tactic"
    tactic = tactics[0]
    assert tactic["name"] == "Execution"
    assert tactic["x_mitre_shortname"] == "execution"
