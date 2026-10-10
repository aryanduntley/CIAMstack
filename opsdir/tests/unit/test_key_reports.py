"""Key reports on the mini estate (in memory): where an environment keeps each key and secret (rotations overdue as of
a day marked; a credential it doesn't bind unbound only where its adapters require it), how spread out each credential
is, and everything a rotation touches."""
import datetime as dt

import pytest

from opsdir.connectors.keys import keys_report
from opsdir.core.environment import env_dn
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.naming import credential_dn
from opsdir.domains.pki.reports import rotation_impact_rows, sprawl_rows
import mini_estate

ALPHA = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
BETA = "env=prod,cloud=beta,ou=environments,dc=ciam-ops"
CERT = "cn=signing-2026,ou=certificates,dc=ciam-ops"
# a certificate keyed by signing-key, presented by alpha's service name; a config file whose setting links to it
USES = tuple(parse(f"""dn: ou=certificates,dc=ciam-ops
changetype: add
objectClass: top
objectClass: organizationalUnit
ou: certificates

dn: {CERT}
changetype: add
objectClass: top
objectClass: ciamCertificate
cn: signing-2026
ciamFingerprint: AB:CD
ciamNotAfter: 20270101000000Z
ciamCertPurpose: tls-server
ciamSubjectAltName: sso.example.test
ciamKeyRole: signing-key

dn: cn=svc-sso,ou=bindings,{ALPHA}
changetype: modify
add: ciamTlsCertificate
ciamTlsCertificate: {CERT}
-

dn: ou=config-files,dc=ciam-ops
changetype: add
objectClass: top
objectClass: organizationalUnit
ou: config-files

dn: cn=app.properties,ou=config-files,dc=ciam-ops
changetype: add
objectClass: top
objectClass: ciamConfigFile
cn: app.properties
ciamFormat: java-properties
ciamRepoPath: conf/app.properties
ciamCaptureLevel: settings
ciamTargetRole: web

dn: cn=s1,cn=app.properties,ou=config-files,dc=ciam-ops
changetype: add
objectClass: top
objectClass: ciamConfigSetting
cn: s1
ciamLocator: signing.key
ciamValueFrom: signing-key#ciamRefUri
"""))


def estate(alpha=None, beta=None, extra=(), **credential):
    return mini_estate.directory((*mini_estate.credential_changes(alpha, beta, **credential), *extra))


# the fake provider requires the signing key; a product no environment runs requires it too
SIGNING = mini_estate.FAKE._replace(required_roles=("signing-key",))
OTHER = mini_estate.FAKE._replace(name="other", applies=lambda m: False, required_roles=("signing-key",),
                                  products=(("Other", ">=1"),))


def placement(d, spec, as_of=None, installed=(SIGNING,)):
    return keys_report(installed).from_directory(d, env_dn(spec), as_of)


def by_name(rows, role_column=2):
    """Rows by credential name, or by role when no credential describes it."""
    return {r[0] if r[0] != "-" else r[role_column]: r for r in rows}


def test_placement_lists_every_credential_where_the_environment_keeps_it():
    d = estate(alpha={"ciamProtectionLevel": "hsm", "ciamAutoRotate": "TRUE", "ciamLastRotated": "20260301000000Z",
                      "ciamReplicaRegion": ("region-2", "region-3"), "ciamKeyUser": "role/web"})
    row = by_name(placement(d, "alpha/prod"))["signing-key"]
    assert row == ("signing-key", "private-key", "signing-key", "fake", "fake://secrets/alpha/signing", "hsm", "yes",
                   "2026-05-30", "region-2, region-3", "role/web", "ok")


def test_placement_shows_unbound_credentials_and_undocumented_bindings():
    rows = by_name(placement(estate(alpha={}), "beta/prod"))
    assert rows["signing-key"][-1] == "UNBOUND"
    alpha = by_name(placement(estate(alpha={}), "alpha/prod"))
    assert alpha["disk-encryption"][-1] == "undocumented: no credential describes this role"


def test_a_credential_nothing_in_the_environment_requires_is_not_used_there():
    d = estate(alpha={})
    assert by_name(placement(d, "beta/prod", installed=(mini_estate.FAKE, OTHER)))["signing-key"][-1] == \
        "not used here: only Other requires it"
    assert by_name(placement(d, "beta/prod", installed=(mini_estate.FAKE,)))["signing-key"][-1] == \
        "not used here: nothing here requires it"


def test_placement_flags_software_protection_of_a_key_that_requires_an_hsm_and_names_the_carried_over_source():
    d = estate(alpha={}, beta={"ciamMaterialFrom": f"cn=secret-signing-key,ou=bindings,{ALPHA}",
                               "ciamProtectionLevel": "software"}, ciamHsmRequired="TRUE")
    assert by_name(placement(d, "beta/prod"))["signing-key"][-1] == \
        "HSM required, the store protects it in software; carried over from alpha/prod"
    assert by_name(placement(estate(alpha={}, ciamHsmRequired="TRUE"), "alpha/prod"))["signing-key"][-1] == \
        "HSM required, protection level not recorded"


def test_sprawl_counts_environments_stores_copies_certificates_and_linked_settings():
    d = estate(alpha={"ciamCopyRef": "fake://pam/safe-1/signing"}, beta={}, extra=USES)
    rows = by_name(sprawl_rows(d), role_column=1)
    assert rows["signing-key"] == ("signing-key", "signing-key", "private-key", "carry-over", "alpha/prod, beta/prod",
                                   "fake", 1, "signing-2026", 1, "", "")
    assert rows["disk-encryption"][-1] == "no credential describes this role"


def test_sprawl_reports_a_credential_bound_nowhere():
    assert by_name(sprawl_rows(estate()), role_column=1)["signing-key"][-1] == "bound in no environment"


def test_rotation_impact_names_every_binding_copy_setting_certificate_and_its_users():
    d = estate(alpha={"ciamCopyRef": "fake://pam/safe-1/signing"}, beta={"ciamAutoRotate": "TRUE"}, extra=USES,
               ciamContinuityReason="partners trust the signing certificate")
    steps = [(step, what, where) for step, what, where, _ in rotation_impact_rows(d, credential_dn("signing-key"))]
    assert steps == [
        ("carry-over", "every environment receives the same new material, together: partners trust the signing "
                       "certificate", ""),
        ("rotate", "fake://secrets/alpha/signing", "alpha/prod"),
        ("update copy", "fake://pam/safe-1/signing", "alpha/prod"),
        ("rotate (automatic)", "fake://secrets/beta/signing", "beta/prod"),
        ("re-render setting", "app.properties: signing.key", "web"),
        ("re-issue certificate", "signing-2026", "sso.example.test"),
        ("service presents it", "sso.example.test", "alpha/prod")]


def test_rotation_impact_of_a_certificate_starts_from_its_key():
    d = estate(alpha={}, extra=USES)
    steps = [step for step, *_ in rotation_impact_rows(d, CERT)]
    assert steps == ["carry-over", "rotate", "re-render setting", "re-issue certificate", "service presents it"]


def test_rotation_impact_refuses_anything_else():
    with pytest.raises(SystemExit, match="not a credential or certificate"):
        rotation_impact_rows(estate(), ALPHA)


def test_an_overlay_shares_its_bases_key_and_rotation_impact_says_so():
    stage = tuple(parse("dn: env=stage,cloud=alpha,ou=environments,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                        f"objectClass: ciamEnvironment\nenv: stage\nciamOverlayOf: {ALPHA}\n"))
    d = estate(alpha={}, extra=stage)
    assert by_name(sprawl_rows(d), role_column=1)["signing-key"][4] == "alpha/prod, alpha/stage"
    assert [(step, where) for step, _, where, _ in rotation_impact_rows(d, credential_dn("signing-key"))][:2] == [
        ("carry-over", ""), ("rotate", "alpha/prod (shared with alpha/stage)")]


def test_a_rotation_due_before_the_as_of_date_is_marked_overdue():
    d = estate(alpha={"ciamLastRotated": "20260301000000Z"})           # rotated every 90 days: due 2026-05-30
    assert by_name(placement(d, "alpha/prod", dt.date(2026, 5, 30)))["signing-key"][-1] == "ok"
    assert by_name(placement(d, "alpha/prod", dt.date(2026, 5, 31)))["signing-key"][-1] == \
        "rotation overdue (due 2026-05-30)"
