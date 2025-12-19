"""Integration checks for GroupsClient using real ATT&CK data."""

import pytest


@pytest.mark.integration
def test_real_group_alias_lookup(real_client):
    """Verify alias-based lookups return a real intrusion set."""
    groups = real_client.query.groups.get_groups()
    assert groups, "Live ATT&CK data should expose intrusion-set entries"
    first_group = groups[0]
    alias = first_group.aliases[0] if getattr(first_group, "aliases", None) else first_group.name

    matches = real_client.query.groups.get_group_by_alias(alias, case=True)
    assert matches, "Alias lookup should find the group"
    assert matches[0].name == first_group.name
