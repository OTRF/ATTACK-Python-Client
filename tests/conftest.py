"""
Provide pytest fixtures for testing the ATTACK Python Client.

Include a fixture for creating a MitreAttackClient instance backed by a 
local STIX bundle for deterministic testing.
"""

from pathlib import Path

import pytest

from attackcti import MitreAttackClient

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "simple_attack_bundle.json"


@pytest.fixture(scope="module")
def attack_client():
    """Return a client backed by a small STIX bundle for deterministic tests."""
    return MitreAttackClient.from_local(enterprise=str(FIXTURE_PATH))
