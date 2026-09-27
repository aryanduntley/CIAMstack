import os

import pytest

import support


def _reachable(target, variable, create):
    """The DSN if it accepts connections; else a skip with the reason (a failure when OPSDIR_TEST_REQUIRE_DB=1)."""
    error = support.database_error(target)
    if error and os.environ.get("OPSDIR_TEST_REQUIRE_DB") == "1":
        pytest.fail(f"integration database unreachable: {error} (default database: {create})")
    if error:
        pytest.skip(f"integration database unreachable ({error}); set {variable}, or create the default one: {create}")
    return target


@pytest.fixture(scope="session")
def dsn():
    """The integration database (the live record in workspace tests)."""
    return _reachable(support.integration_dsn(os.environ), "OPSDIR_TEST_DSN", support.CREATE_TEST_DB)


@pytest.fixture(scope="session")
def workspace_dsn():
    """The migration workspace database the integration suite uses."""
    return _reachable(support.integration_workspace_dsn(os.environ), "OPSDIR_TEST_WORKSPACE_DSN",
                      support.CREATE_TEST_WORKSPACE_DB)


@pytest.fixture(scope="session")
def snapshot(dsn, tmp_path_factory):
    """{path: text} of every output scripts/snapshot-outputs.sh captures against the integration database."""
    out = tmp_path_factory.mktemp("snapshot") / "out"
    run = support.run_snapshot(dsn, out)
    assert run.returncode == 0, f"snapshot-outputs.sh failed:\n{run.stdout}{run.stderr}"
    return support.read_tree(out)
