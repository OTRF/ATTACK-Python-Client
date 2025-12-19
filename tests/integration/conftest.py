"""
Integration test configuration for the ATT&CK Python Client.

This module provides pytest fixtures for integration tests, including:
- real_client: A MitreAttackClient instance backed by real ATT&CK STIX bundles.
"""

import os

import pytest

from attackcti import MitreAttackClient


@pytest.fixture(scope="session")
def real_client():
    """Provide a MitreAttackClient backed by the real ATT&CK STIX bundles."""
    if os.getenv("RUN_INTEGRATION") not in {"1", "true", "True"}:
        pytest.skip("integration tests require RUN_INTEGRATION=1")
    return MitreAttackClient.from_attack_stix_data()
