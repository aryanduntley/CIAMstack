import base64

import pytest

from opsdir.core.interchange.ldif import LdifRecord, content_entries, fold, parse, write_entry


def test_parse_content_records_with_comments_folding_and_base64():
    text = ("# a comment\n"
            "dn: cn=a,dc=x\n"
            "objectClass: top\n"
            "description: first half\n"
            "  second half\n"
            "mail: a@example.test\n"
            "mail: b@example.test\n"
            "\n\n"
            f"dn: cn=b,dc=x\ncn:: {base64.b64encode('Zoë'.encode()).decode()}\n")
    a, b = parse(text)
    assert a == LdifRecord("cn=a,dc=x", "add", {"objectClass": ("top",), "description": ("first half second half",),
                                                "mail": ("a@example.test", "b@example.test")}, ())
    assert b.attrs == {"cn": ("Zoë",)}


def test_parse_change_records():
    text = ("dn: cn=a,dc=x\nchangetype: modify\nreplace: ciamFqdn\nciamFqdn: new.test\n-\n"
            "add: ciamChangeRef\nciamChangeRef: cn=CHG-1\nciamChangeRef: cn=CHG-2\n-\ndelete: description\n-\n\n"
            "dn: cn=b,dc=x\nchangetype: delete\n\n"
            "dn: cn=c,dc=x\nchangetype: add\ncn: c\n")
    modify, delete, add = parse(text)
    assert modify.changetype == "modify" and modify.attrs == {}
    assert modify.mods == (("replace", "ciamFqdn", ("new.test",)),
                           ("add", "ciamChangeRef", ("cn=CHG-1", "cn=CHG-2")), ("delete", "description", ()))
    assert (delete.changetype, delete.attrs, delete.mods) == ("delete", {}, ())
    assert (add.changetype, add.attrs) == ("add", {"cn": ("c",)})


@pytest.mark.parametrize("text", ["cn: no dn first\n", "dn: cn=a\nnot an attribute line\n"])
def test_parse_rejects_malformed_records(text):
    with pytest.raises(ValueError):
        tuple(parse(text))


def test_fold_keeps_short_lines_and_folds_long_ones_at_width():
    assert fold("short", 10) == ("short",)
    lines = fold("x" * 25, 10)
    assert lines == ("x" * 10, " " + "x" * 9, " " + "x" * 6)
    assert all(len(line) <= 10 for line in lines)


def test_write_entry_puts_naming_attributes_first_and_base64_encodes_unsafe_values():
    text = write_entry("cn=a,dc=x", ("top", "ciamObject"),
                       {"description": (" leading space",), "mail": ("a@x.test",), "cn": ("a",)})
    lines = text.splitlines()
    assert lines[:4] == ["dn: cn=a,dc=x", "objectClass: top", "objectClass: ciamObject", "cn: a"]
    assert lines[4].startswith("description:: ")
    assert text.endswith("\n")


@pytest.mark.parametrize("value", ["plain", " padded ", ":colon", "<angle", "naïve", "two\nlines", "y" * 200])
def test_write_then_parse_round_trips(value):
    attrs = {"cn": ("a",), "description": (value, "second")}
    (r,) = parse(write_entry("cn=a,dc=x", ("top",), attrs))
    assert r.dn == "cn=a,dc=x"
    assert r.attrs == {"objectClass": ("top",), **attrs}


def test_directory_data_is_streamed_tolerantly():
    lines = iter(("version: 1\n", "\n", "# ann\n", "dn: uid=ann,dc=x\n", "objectClass: inetOrgPerson\n",
                  "cn;lang-fr: Anne\n", "CN: Ann\n", f"jpegPhoto:: {base64.b64encode(bytes((255, 216))).decode()}\n",
                  "description: one\n", "  two\n", "labeledURI:< file:///etc/passwd\n", "userPassword:: !!\n",
                  "\n", "search: 2\n", "result: 0 Success\n"))
    (dn, attrs), = content_entries(lines)
    assert dn == "uid=ann,dc=x"
    assert attrs == {"objectclass": ("inetOrgPerson",), "cn": ("Anne", "Ann"), "jpegphoto": (bytes((255, 216)),),
                     "description": ("one two",), "labeleduri": (b"",), "userpassword": (b"",)}
