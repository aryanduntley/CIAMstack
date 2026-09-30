"""Reading an export for `opsdir import`: every file as text under its path, a gzip-compressed file decompressed
under its name without .gz, and files that aren't UTF-8 text left out and named; the import's time, now or when the
export was taken (--at)."""
import datetime as dt
import gzip

import pytest

from opsdir.cli import import_time, read_texts


def test_an_export_directory_is_read_as_text_with_compressed_files_decompressed(tmp_path):
    (tmp_path / "ds-1" / "archived-configs").mkdir(parents=True)
    (tmp_path / "ds-1" / "config.ldif").write_text("dn: cn=config\n")
    (tmp_path / "ds-1" / "archived-configs" / "config-20260920030000Z.gz").write_bytes(gzip.compress(b"dn: cn=old\n"))
    (tmp_path / "ds-1" / "keystore").write_bytes(b"\x00\xff\xfe binary")
    (tmp_path / "ds-1" / "broken.gz").write_bytes(b"not gzip")
    files, skipped = read_texts(tmp_path)
    assert files == {"ds-1/config.ldif": "dn: cn=config\n",
                     "ds-1/archived-configs/config-20260920030000Z": "dn: cn=old\n"}
    assert set(skipped) == {"ds-1/keystore", "ds-1/broken"}


def test_a_single_file_is_read_under_its_name(tmp_path):
    (tmp_path / "config.ldif.gz").write_bytes(gzip.compress(b"dn: cn=config\n"))
    assert read_texts(tmp_path / "config.ldif.gz") == ({"config.ldif": "dn: cn=config\n"}, ())


def test_an_imports_time_is_now_or_when_the_export_was_taken():
    assert import_time("20260930141500Z") == dt.datetime(2026, 9, 30, 14, 15, tzinfo=dt.timezone.utc)
    assert import_time().tzinfo == dt.timezone.utc and import_time().microsecond == 0
    with pytest.raises(SystemExit, match="give the time as YYYYMMDDhhmmssZ"):
        import_time("2026-09-30")
