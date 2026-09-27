import os

import pytest

import support


@pytest.fixture(scope="session")
def dsn():
    """The integration database."""
    return support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB)
