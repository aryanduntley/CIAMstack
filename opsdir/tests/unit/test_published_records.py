"""The records an environment publishes in zones the platform runs (core edge.records.published): service names' A
records, other records, relative names; names in no bound zone or in a zone another party runs left out."""
from opsdir.domains.edge.records import published
from edge_samples import alpha_with_dns


def test_service_names_and_records_in_the_platforms_zones():
    found = {(p.zone, p.name, p.type, p.values, p.ttl) for p in published(alpha_with_dns())}
    assert found == {("example.test", "sso", "A", ("10.1.9.10",), 300),
                     ("example.test", "@", "TXT", ("v=opsdir1",), 300),
                     ("example.test", "@", "MX", ("10 mail.example.test",), 3600)}      # the partner's zone left out
