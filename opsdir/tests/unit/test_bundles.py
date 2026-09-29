"""Bundles recorded by repo path and digest (never their content), and verification against a repo checkout
(on the mini estate)."""
import hashlib

from opsdir.connectors.capture import bundle_changes, capture_changes, verification, verify_paths
from opsdir.core.formats import JAVA_PROPERTIES
from opsdir.core.secrets import CORE_PATTERNS
from opsdir.domains.configuration.bundles import bundle_rows, content_concerns, content_digest
import mini_estate
from mini_estate import FAKE

LOGIN = {"login.html": b"<html><body>Sign in</body></html>\n", "css/site.css": b"body { margin: 0 }\n"}


def recorded(*changes):
    return mini_estate.directory(tuple(r for c in changes for r in c))


def test_a_single_file_digests_as_itself_and_a_directory_as_its_sorted_listing():
    assert content_digest({"": b"echo hi\n"}) == hashlib.sha256(b"echo hi\n").hexdigest()
    listing = "".join(f"{hashlib.sha256(LOGIN[p]).hexdigest()}  {p}\n" for p in sorted(LOGIN))
    assert content_digest(LOGIN) == hashlib.sha256(listing.encode()).hexdigest()
    assert content_digest(dict(reversed(list(LOGIN.items())))) == content_digest(LOGIN)


def test_a_bundle_is_recorded_without_its_content():
    changes, notices = bundle_changes(mini_estate.directory(), "login-ui", "am/ui/login", "template", LOGIN,
                                      "html", "2.4.0", installed=(FAKE,))
    d = recorded(changes)
    assert bundle_rows(d) == [("login-ui", "template", "2.4.0", "html", "am/ui/login", "", content_digest(LOGIN))]
    assert notices == (f"login-ui: template bundle at am/ui/login (2 file(s), sha256 {content_digest(LOGIN)[:12]})",)
    assert b"Sign in".decode() not in repr([e.attrs for e in d.entries.values()])


def test_what_in_a_bundle_may_be_secret_is_noticed_binary_files_are_skipped():
    content = {"deploy.sh": b"#!/bin/sh\nexport DB_PASSWORD=Hunter2Hunter2\n", "logo.png": b"\x89PNG\x00\xff"}
    assert content_concerns(content, CORE_PATTERNS) == (
        "deploy.sh line 2: secret material (secret-assignment)", "deploy.sh line 2: DB_PASSWORD is given a value")
    _, notices = bundle_changes(mini_estate.directory(), "deploy", "scripts/deploy", "script", content,
                                installed=(FAKE,))
    assert notices[1] == "deploy: may hold secret material: deploy.sh line 2: secret material (secret-assignment)"


def test_verification_compares_bundles_and_captured_files_with_the_checkout():
    d = recorded(bundle_changes(mini_estate.directory(), "login-ui", "am/ui/login", "template", LOGIN,
                                installed=(FAKE,))[0],
                 capture_changes(mini_estate.directory(), JAVA_PROPERTIES, "a=1\n", "app", "conf/app.properties",
                                 installed=(FAKE,))[0],
                 capture_changes(mini_estate.directory(), JAVA_PROPERTIES, "b=2\n", "gone", "conf/gone.properties",
                                 installed=(FAKE,))[0])
    assert set(verify_paths(d)) == {"am/ui/login", "conf/app.properties", "conf/gone.properties"}
    headers, rows = verification(d, {"am/ui/login": {**LOGIN, "login.html": b"<html>edited</html>\n"},
                                     "conf/app.properties": {"": b"a=1\n"}, "conf/gone.properties": None},
                                 installed=(FAKE,))
    assert headers == ("kind", "name", "repo path", "status", "detail")
    assert rows == (("bundle", "login-ui", "am/ui/login", "changed", ""),
                    ("config file", "app", "conf/app.properties", "same as the record", ""),
                    ("config file", "gone", "conf/gone.properties", "missing", ""))
    _, again = verification(d, {"am/ui/login": LOGIN, "conf/app.properties": {"": b"a=2\n"}}, installed=(FAKE,))
    assert [row[3] for row in again] == ["unchanged", "differs from the record", "missing"]
