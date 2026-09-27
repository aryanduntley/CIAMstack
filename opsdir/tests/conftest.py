import pytest

import support


@pytest.fixture(scope="session")
def check_findings():
    """scripts/check-findings.py as a module (its AS_OF and pure comparison)."""
    return support.load_script("check-findings.py")


@pytest.fixture(scope="session")
def as_of(check_findings):
    return check_findings.AS_OF


@pytest.fixture(scope="session")
def estate():
    """{'before': the synthetic estate as loaded, 'after': with the approved changes applied}."""
    return {"before": support.fixture_directory(), "after": support.fixture_directory(support.APPROVED)}
