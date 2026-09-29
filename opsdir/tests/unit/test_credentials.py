"""Credentials and where each environment keeps them (in memory, on the mini estate): a credential is joined to its
bindings by role, certificates and captured settings point at the same role, and rotation is due from the binding's
last rotation and the credential's policy."""
import datetime as dt

from opsdir.core.directory import get, one
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.credentials import (binding_for, bindings_everywhere, certificates_keyed_by,
                                            credential_for_role, credentials, material_bindings, rotate_by)
from opsdir.domains.pki.naming import credential_dn
import mini_estate

CERTIFICATE = tuple(parse("dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                    "objectClass: organizationalUnit\nou: certificates\n\n"
                    "dn: cn=signing-2026,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                    "objectClass: ciamCertificate\ncn: signing-2026\nciamFingerprint: AB:CD\n"
                    "ciamNotAfter: 20270101000000Z\nciamCertPurpose: saml-signing\nciamKeyRole: signing-key\n"))


def test_a_credential_is_joined_to_each_environments_binding_by_role():
    d = mini_estate.directory(mini_estate.credential_changes(alpha={"ciamProtectionLevel": "hsm"}, beta={}))
    cred = get(d, credential_dn("signing-key"))
    assert credentials(d) == (cred,) and credential_for_role(d, "signing-key") == cred
    alpha, beta = env_model(d, "alpha/prod"), env_model(d, "beta/prod")
    assert one(binding_for(alpha, cred), "ciamRefUri") == "fake://secrets/alpha/signing"
    assert one(binding_for(alpha, cred), "ciamProtectionLevel") == "hsm"
    assert one(binding_for(beta, cred), "ciamRefUri") == "fake://secrets/beta/signing"
    assert [env for env, _ in bindings_everywhere(d, "signing-key")] == [alpha.dn, beta.dn]


def test_material_bindings_are_the_secret_key_and_certificate_references():
    d = mini_estate.directory(mini_estate.credential_changes(alpha={}))
    assert [one(b, "ciamBindingRole") for b in material_bindings(env_model(d, "alpha/prod"))] == \
        ["disk-encryption", "signing-key"]


def test_an_environment_without_the_role_has_no_binding_for_it():
    d = mini_estate.directory(mini_estate.credential_changes(alpha={}))
    assert binding_for(env_model(d, "beta/prod"), credential_for_role(d, "signing-key")) is None
    assert credential_for_role(d, "no-such-role") is None


def test_certificates_name_the_role_of_their_private_key():
    d = mini_estate.directory((*mini_estate.credential_changes(), *CERTIFICATE))
    assert [one(c, "cn") for c in certificates_keyed_by(d, "signing-key")] == ["signing-2026"]


def test_rotation_is_due_the_policy_period_after_the_last_rotation():
    d = mini_estate.directory(mini_estate.credential_changes(alpha={"ciamLastRotated": "20260301000000Z"}, beta={}))
    cred = credential_for_role(d, "signing-key")
    assert rotate_by(cred, binding_for(env_model(d, "alpha/prod"), cred)) == dt.date(2026, 5, 30)
    assert rotate_by(cred, binding_for(env_model(d, "beta/prod"), cred)) is None     # never rotated: not recorded
