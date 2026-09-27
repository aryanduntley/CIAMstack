"""The installed adapters (and domains) define the vocabulary the showcase uses."""
from opsdir.connectors.registry import vocabulary


def test_domains_and_adapters_define_the_values():
    rows = set(vocabulary())
    assert ("ciamServerRole", "ds", "directory") in rows
    assert ("ciamCloudProvider", "aws", "aws") in rows and ("ciamCloudProvider", "azure", "azure") in rows
    assert ("ciamServerRole", "pf-engine", "pingfederate") in rows
    assert len(rows) == len(vocabulary())                      # no repeats
