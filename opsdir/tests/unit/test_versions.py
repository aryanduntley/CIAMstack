"""Versions as data: product version values and declared ranges."""
import pytest

from opsdir.core.versions import in_range, product_version


@pytest.mark.parametrize("value, expected", [("SomeDS 7.5.1", ("SomeDS", "7.5.1")),
                                             ("Some Product Name 12.1.4", ("Some Product Name", "12.1.4")),
                                             ("7.5", ("7.5", "")), (None, ("", ""))])
def test_the_version_is_the_last_word(value, expected):
    assert product_version(value) == expected


def test_ranges_are_pep_440_specifiers():
    assert in_range("7.5.1", ">=7,<9") and not in_range("9.0", ">=7,<9") and in_range("8.0.0rc1", ">=7,<9")
    assert not in_range("not a version", ">=7") and not in_range("7.5", "not a range")
