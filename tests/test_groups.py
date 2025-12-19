"""Validation for GroupsClient helpers using the fixture data."""

from attackcti.utils.stix import as_dict


def test_get_groups_and_alias_match(attack_client):
    """GroupsClient should expose the fixture intrusion-set and support alias lookups."""
    groups = attack_client.query.groups.get_groups()
    assert groups, "Expected fixture to contain at least one group"
    first = groups[0]
    assert first.name == "Sample Group"

    alias_matches = attack_client.query.groups.get_group_by_alias("Sample Group Alias", case=True)
    assert alias_matches, "Alias search should find the fixture group"
    alias_entry = as_dict(alias_matches[0])
    assert alias_entry.get("aliases") and alias_entry["aliases"][0] == "Sample Group Alias"
