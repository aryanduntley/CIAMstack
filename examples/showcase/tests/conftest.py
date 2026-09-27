import os

import pytest

import showcase_support
import support


@pytest.fixture(scope="session")
def check_findings():
    """scripts/check-findings.py as a module (its AS_OF and pure comparison)."""
    return showcase_support.load_script("check-findings.py")


@pytest.fixture(scope="session")
def as_of(check_findings):
    return check_findings.AS_OF


@pytest.fixture(scope="session")
def estate():
    """{'before': the example estate as loaded, 'after': with the approved changes applied}."""
    return {"before": showcase_support.fixture_directory(),
            "after": showcase_support.fixture_directory(showcase_support.APPROVED)}


@pytest.fixture(scope="session")
def dsn():
    """The integration database (the live record in workspace tests)."""
    return support.reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB)


@pytest.fixture(scope="session")
def workspace_dsn():
    """The migration workspace database the integration suite uses."""
    return support.reachable(support.integration_workspace_dsn(os.environ), "OPSDIR_TEST_WORKSPACE_DSN",
                             support.CREATE_TEST_WORKSPACE_DB)


@pytest.fixture(scope="session")
def snapshot(dsn, tmp_path_factory):
    """{path: text} of every output scripts/snapshot-outputs.sh captures against the integration database."""
    out = tmp_path_factory.mktemp("snapshot") / "out"
    run = showcase_support.run_snapshot(dsn, out)
    assert run.returncode == 0, f"snapshot-outputs.sh failed:\n{run.stdout}{run.stderr}"
    return support.read_tree(out)
