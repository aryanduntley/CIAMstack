"""The showcase data files are exactly what the example_estate fixture builds."""
from example_estate.build import build
from showcase_support import DATA


def test_synthetic_estate_is_exactly_what_the_fixture_builds():
    n, files = build()
    on_disk = {p.name: p.read_text() for p in DATA.iterdir() if p.suffix in (".ldif", ".json")}
    assert files == on_disk
    assert n == sum(1 for f in on_disk.values() for line in f.splitlines() if line.startswith("dn: "))
