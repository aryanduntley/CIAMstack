"""The record database's posture rules (connectors.posture), over made-up connection facts: what passes, what a
development record only notes and what fails a production one."""
from opsdir.connectors.posture import FAIL, INFO, OK, WARN, failed, posture_rows
from opsdir.core.directory import make_directory
from opsdir.core.interchange.ldif import parse
from opsdir.store.migrations import migration
from opsdir.store.postgres import PostureFacts

KNOWN = (migration("0001_core.sql", "x"), migration("0002_more.sql", "y"))
DEV = PostureFacts(170009, "localhost", "prefer", "", True, True, False, False, True, True, "opsdir", "opsdir", False,
                   "opsdir", True, True, ((1, "core"), (2, "more")))
PROD = DEV._replace(host="db.example.internal", sslmode="verify-full", sslrootcert="/etc/ca.pem", password_given=False,
                    dev_password=False, dbname="record", user="opsdir_app", schema_owner="opsdir_owner",
                    owns_schema=False, can_create=False)
UUID = "3f2b9c1e-8d4a-4c6b-9e2f-1a7d5c3b8e90"


def directory(production=False, org=None, clouds=()):
    text = ""
    if production:
        text += ("dn: cn=deployment,ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\n"
                 "cn: deployment\nciamEstateValue: production\n\n")
    if org:
        text += (f"dn: cn=record,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamRecordIdentity\ncn: record\n"
                 f"ciamOrgCode: {org}\nciamRecordId: {UUID}\n\n")
    for cloud in clouds:
        text += (f"dn: cloud={cloud},ou=environments,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamCloud\n"
                 f"cloud: {cloud}\n\ndn: env=prod,cloud={cloud},ou=environments,dc=ciam-ops\nobjectClass: top\n"
                 "objectClass: ciamEnvironment\nenv: prod\n\n")
    rows = [(r.dn, tuple(r.attrs.get("objectClass", ())), {k: v for k, v in r.attrs.items() if k != "objectClass"})
            for r in parse(text)] if text else []
    return make_directory((), {}, rows)


def status(rows, check):
    return next(s for c, s, _ in rows if c == check)


def test_a_development_record_on_the_dev_defaults_only_notes_them():
    rows = posture_rows(DEV, directory(), KNOWN)
    assert rows[0] == ("deployment", INFO, "development")
    assert status(rows, "sign-in") == INFO and status(rows, "development defaults") == INFO
    assert status(rows, "login privileges") == INFO and status(rows, "record identity") == WARN
    assert status(rows, "schema") == OK and failed(rows) == 0


def test_a_production_record_on_the_dev_defaults_fails():
    rows = posture_rows(DEV, directory(production=True), KNOWN)
    assert {c for c, s, _ in rows if s == FAIL} == {"sign-in", "development defaults", "login privileges",
                                                   "record identity"}


def test_a_hardened_production_record_passes():
    rows = posture_rows(PROD, directory(production=True, org="collins"), KNOWN)
    assert failed(rows) == 0 and status(rows, "tls") == OK and status(rows, "sign-in") == OK


def test_tls_off_the_host():
    weaker = PROD._replace(sslmode="require")
    assert status(posture_rows(weaker, directory(), KNOWN), "tls") == FAIL
    assert status(posture_rows(weaker, directory(), KNOWN, allowed="require"), "tls") == WARN


def test_sign_in_methods():
    assert dict((c, d) for c, _, d in posture_rows(PROD._replace(used_gssapi=True, used_password=False), directory(),
                                                   KNOWN))["sign-in"] == "Kerberos (GSSAPI)"
    cert = PROD._replace(client_certificate=True, used_password=False)
    assert dict((c, d) for c, _, d in posture_rows(cert, directory(), KNOWN))["sign-in"] == "client certificate"


def test_old_servers_superusers_and_migrations():
    rows = posture_rows(PROD._replace(server_version=160015, superuser=True, applied=((1, "core"), (3, "x"))),
                        directory(), KNOWN)
    assert status(rows, "server version") == FAIL and status(rows, "login privileges") == WARN
    assert "doesn't know: 0003" in dict((c, d) for c, _, d in rows)["schema"]
    pending = posture_rows(PROD._replace(applied=((1, "core"),)), directory(), KNOWN)
    assert "1 migration(s) pending, from 0002" in dict((c, d) for c, _, d in pending)["schema"]
    empty = posture_rows(PROD._replace(schema_owner="", applied=()), directory(), KNOWN)
    assert "run opsdir init" in dict((c, d) for c, _, d in empty)["schema"]


def test_cloud_names_against_the_org_code():
    rows = posture_rows(PROD, directory(org="collins", clouds=("collins-aws", "aws-legacy")), KNOWN)
    assert ("cloud names", INFO, "not starting with collins-: aws-legacy (a merger with another company's record "
                                 "would rename them)") in rows
    assert ("cloud names", OK, "all start with collins-") in posture_rows(
        PROD, directory(org="collins", clouds=("collins-aws",)), KNOWN)
    assert not any(c == "cloud names" for c, _, _ in posture_rows(PROD, directory(), KNOWN))


def test_the_servers_tls_minimum_password_hashing_login_attributes_and_public_rights_are_checked():
    hardened = PROD._replace(ssl_min_version="TLSv1.2", password_encryption="scram-sha-256")
    rows = posture_rows(hardened, directory(production=True, org="exa"), KNOWN)
    assert [status(rows, c) for c in ("tls minimum", "password hashing", "login attributes", "public rights")] == \
        [OK, OK, OK, OK]
    weak = hardened._replace(ssl_min_version="TLSv1", password_encryption="md5", role_flags=("createdb", "bypassrls"),
                             public_rights=("TEMPORARY",))
    prod, dev = (posture_rows(weak, directory(production=p, org="exa"), KNOWN) for p in (True, False))
    assert [status(prod, c) for c in ("tls minimum", "password hashing", "login attributes", "public rights")] == \
        [FAIL, FAIL, FAIL, WARN]
    assert [status(dev, c) for c in ("tls minimum", "password hashing", "login attributes", "public rights")] == \
        [WARN, WARN, WARN, INFO]
    detail = dict((c, d) for c, _, d in prod)
    assert "opsdir_app can create databases, bypass row security" in detail["login attributes"]
    assert "revoke temporary on database record from public" in detail["public rights"]
    assert status(posture_rows(PROD, directory(), KNOWN), "tls minimum") == INFO        # unreadable: noted only


def settings(**values):
    return "".join(f"dn: cn={name},ou=settings,dc=ciam-ops\nobjectClass: top\nobjectClass: ciamEstateSetting\n"
                   f"cn: {name}\nciamEstateValue: {value}\n\n" for name, value in values.items())


def with_settings(base, text):
    rows = [(r.dn, tuple(r.attrs.get("objectClass", ())), {k: v for k, v in r.attrs.items() if k != "objectClass"})
            for r in parse(text)]
    return make_directory((), {}, [*((e.dn, e.classes, e.attrs) for e in base.entries.values()), *rows])


def test_default_privileges_the_client_library_tiers_and_recovery_targets():
    rows = posture_rows(PROD, directory(production=True), KNOWN)
    assert status(rows, "default privileges") == OK and status(rows, "client library") == INFO
    assert status(rows, "approval tiers") == INFO and status(rows, "recovery targets") == WARN
    granted = PROD._replace(default_acls=(("opsdir", "r", "PUBLIC", "SELECT"),), libpq_version=150004,
                            psycopg_impl="c", sslrootcert="system")
    rows = posture_rows(granted, directory(production=True), KNOWN)
    detail = dict((c, d) for c, _, d in rows)
    assert status(rows, "default privileges") == WARN and "SELECT on new tables in opsdir to PUBLIC" in detail[
        "default privileges"]
    assert status(rows, "client library") == FAIL and "needs libpq 16" in detail["client library"]
    assert status(posture_rows(granted._replace(libpq_version=170002), directory(), KNOWN), "client library") == OK
    d = with_settings(directory(production=True), settings(**{"approvals-required": "*=1, collins-aws/prod=2",
                                                              "recovery-rpo": "15m", "recovery-rto": "4h"}))
    rows = posture_rows(PROD, d, KNOWN)
    assert status(rows, "approval tiers") == OK and status(rows, "recovery targets") == OK
    assert dict((c, x) for c, _, x in rows)["recovery targets"].startswith("RPO 15m, RTO 4h")
