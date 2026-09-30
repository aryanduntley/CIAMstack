"""The showcase data files and the directory servers' configuration exports are exactly what the example_estate
fixture builds."""
import gzip

from example_estate.build import build, exports
from showcase_support import SHOWCASE, DATA


def test_synthetic_estate_is_exactly_what_the_fixture_builds():
    n, files = build()
    on_disk = {p.name: p.read_text() for p in DATA.iterdir() if p.suffix in (".ldif", ".json")}
    assert files == on_disk
    assert n == sum(1 for f in on_disk.values() for line in f.splitlines() if line.startswith("dn: "))


def test_the_directory_servers_exports_are_exactly_what_the_fixture_builds():
    root = SHOWCASE / "exports"
    on_disk = {p.relative_to(root).as_posix(): (gzip.decompress(p.read_bytes()).decode() if p.suffix == ".gz"
                                                 else p.read_text())
               for p in sorted((root / "ds-config").rglob("*")) if p.is_file()}
    assert exports() == on_disk
