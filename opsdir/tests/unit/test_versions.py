"""Versions as data: product version values and declared ranges."""
import pytest

from opsdir.core.versions import holds, in_range, product_version


@pytest.mark.parametrize("value, expected", [("SomeDS 7.5.1", ("SomeDS", "7.5.1")),
                                             ("Some Product Name 12.1.4", ("Some Product Name", "12.1.4")),
                                             ("7.5", ("7.5", "")), (None, ("", ""))])
def test_the_version_is_the_last_word(value, expected):
    assert product_version(value) == expected


def test_ranges_are_pep_440_specifiers():
    assert in_range("7.5.1", ">=7,<9") and not in_range("9.0", ">=7,<9") and in_range("8.0.0rc1", ">=7,<9")
    assert not in_range("not a version", ">=7") and not in_range("7.5", "not a range")


def test_a_declaration_for_some_versions_holds_for_what_the_role_records_else_the_newest():
    assert holds(None, ()) and holds(None, ("SomeDS 7.1",))
    assert holds("<7.3", ("SomeDS 7.2.5",)) and not holds("<7.3", ("SomeDS 8.1.2",))
    assert holds("<7.3", ("SomeDS 8.1.2", "SomeDS 7.2.5"))                  # one server of the role writes it
    assert not holds("<7.3", ()) and holds(">=2025.3", ())                    # none recorded: the newest release
