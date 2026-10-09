"""A PingFederate bulk export read into the record: SP and IdP connections and OAuth clients as integrations (merged
with the record's, keeping owners, populations and claim transforms), claims linked to user-schema records, the
certificates of PingFederate's own keys and of partners matched by fingerprint, secrets never read, data stores
recorded (in detail: test_pingfederate_datastores), every resource type of the export read, importing again changing
nothing, and the adapter's own rendered files reading back as they were."""
import json
from pathlib import Path

from opsdir.connectors.importing import import_changes
from opsdir.core.directory import fingerprint, get, make_directory, one, values
from opsdir.domains.directory.naming import CONSUMERS, USER_SCHEMA
from opsdir.domains.federation.naming import IDENTITY_SERVICES, INTEGRATIONS
from opsdir.domains.pki.naming import CERTIFICATES
from opsdir_adapter_pingfederate.importer import read_export
from opsdir_adapter_pingfederate.naming import DATA_STORES
from types import SimpleNamespace

from opsdir_adapter_pingfederate.admin_api import admin_api_files

EXPORT = Path(__file__).resolve().parent / "bulk-export"
SIGNING_FP = "18:50:45:3C:96:D7:6C:B8:F5:90:6A:4B:06:37:F9:99:AE:16:65:5C:A3:29:EC:90:34:04:37:FA:10:28:B6:99"
PORTAL = f"cn=customer-portal,{INTEGRATIONS}"
SSO = f"cn=sso,{IDENTITY_SERVICES}"
ENV = "env=prod,cloud=main,ou=environments,dc=ciam-ops"


def _row(dn, classes, **attrs):
    return dn, ("top", *classes), {k: [v] if isinstance(v, str) else list(v) for k, v in attrs.items()}


def _record():
    return make_directory((), {}, (
        *(_row(f"cn={a},{USER_SCHEMA}", ("ciamUserAttribute",), cn=a, ciamLdapName=a, ciamPiiClass="low")
          for a in ("mail", "companyId")),
        *(_row(f"cn={o},ou=owners,dc=ciam-ops", ("ciamParty",), cn=o) for o in ("portal-team", "platform")),
        _row(SSO, ("ciamIdentityService",), cn="sso", ciamBaseUrl="https://sso.example.test",
             ciamTargetRole="pf-engine"),
        _row(PORTAL, ("ciamIntegration",), cn="customer-portal", ciamProtocolType="saml2-sp",
             ciamEntityId="https://portal.example.test/saml/sp", ciamAcsUrl="https://old.example.test/acs",
             ciamOwner="cn=portal-team,ou=owners,dc=ciam-ops", ciamPopulation="customers", ciamServedBy=SSO),
        _row(f"ou=claims,{PORTAL}", ("organizationalUnit",), ou="claims"),
        _row(f"cn=email,ou=claims,{PORTAL}", ("ciamClaimMap",), cn="email", ciamClaimName="email",
             ciamSourceAttribute=f"cn=mail,{USER_SCHEMA}", ciamTransform="lowercase"),
        _row(f"cn=pf-signing-2025,{CERTIFICATES}", ("ciamCertificate",), cn="pf-signing-2025",
             ciamFingerprint=SIGNING_FP, ciamNotAfter="20270630000000Z", ciamCertPurpose="saml-signing",
             ciamKeyRole="pf-signing-key", ciamOwner="cn=platform,ou=owners,dc=ciam-ops"),
        _row(f"cn=pf-ds-svc,{CONSUMERS}", ("ciamConsumer",), cn="pf-ds-svc",
             ciamBindDn="uid=pf-svc,ou=service-accounts,dc=example,dc=test"),
        _row(f"cn=ds-1,{ENV}", ("ciamServer",), cn="ds-1", ciamServerRole="ds",
             ciamHostname="ds-1.internal.example.test"),
        _row(f"cn=svc-ldaps,ou=bindings,{ENV}", ("ciamServiceName",), cn="svc-ldaps", ciamFqdn="ldap.example.test",
             ciamBindingRole="ds-ldaps-service")))


def _files():
    return {p.relative_to(EXPORT).as_posix(): p.read_text() for p in EXPORT.rglob("*") if p.is_file()}


def _after(d, imported):
    scopes = [s.lower() for s, _ in imported.groups]
    kept = {n: e for n, e in d.entries.items() if not any(n == s or n.endswith("," + s) for s in scopes)}
    added = {e.norm: e for e in (*(c for c in imported.containers if c.norm not in d.entries),
                                 *(e for _, es in imported.groups for e in es))}
    return d._replace(entries={**kept, **added})


def test_an_sp_connection_updates_the_integration_keeping_what_the_export_doesnt_hold():
    d = _record()
    imported = read_export(_files(), d, ())
    after = _after(d, imported)
    portal = get(after, PORTAL)
    assert (one(portal, "ciamAcsUrl"), one(portal, "ciamSamlBinding"), one(portal, "ciamOwner"),
            one(portal, "ciamPopulation")) == ("https://portal.example.test/saml/acs", "HTTP-POST",
                                               "cn=portal-team,ou=owners,dc=ciam-ops", "customers")
    assert values(portal, "ciamUsesCertificate") == (f"cn=pf-signing-2025,{CERTIFICATES}",)
    email, org = get(after, f"cn=email,ou=claims,{PORTAL}"), get(after, f"cn=org,ou=claims,{PORTAL}")
    assert one(email, "ciamTransform") == "lowercase"
    assert one(org, "ciamSourceAttribute") == f"cn=companyId,{USER_SCHEMA}"
    assert "SP connection customer-portal: claims from values the record has no user-schema record for, not " \
           "recorded: tier (gold)" in imported.notices


def test_partners_and_clients_new_to_the_record_are_added_and_named():
    d = _record()
    imported = read_export(_files(), d, ())
    after = _after(d, imported)
    partner = get(after, f"cn=partner-idp,{INTEGRATIONS}")
    assert (one(partner, "ciamProtocolType"), one(partner, "ciamJitBaseDn"), one(partner, "ciamServedBy")) == \
        ("saml2-idp", "ou=partners,ou=people,dc=example,dc=test", SSO)
    cert = get(after, one(partner, "ciamUsesCertificate"))
    assert (one(cert, "ciamCertPurpose"), one(cert, "ciamNotAfter"), one(cert, "ciamIssuer")) == \
        ("partner-signing", "20261102000000Z", "self-signed")
    mobile = get(after, f"cn=mobile,{INTEGRATIONS}")
    assert (values(mobile, "ciamGrantType"), one(mobile, "ciamTokenAuthMethod"), one(mobile, "ciamPkceRequired"),
            values(mobile, "ciamScope")) == (("authorization_code", "refresh_token"), "none", "TRUE",
                                             ("openid", "email"))
    batch = get(after, f"cn=batch,{INTEGRATIONS}")
    assert (values(batch, "ciamGrantType"), one(batch, "ciamTokenAuthMethod")) == \
        (("client_credentials",), "client_secret_basic")
    assert {"client batch: grant types with no single standard name, not recorded: EXTENSION",
            "client batch: its secret is not imported; set pingfedCredentialRole to the secret role each "
         "environment binds it with",
            "new integration partner-idp (idp), not in the record before: give it an owner"} <= set(imported.notices)
    tls = next(c for c in (get(after, dn) for dn in after.entries) if c and one(c, "ciamKeyRole") == "sso-tls-keystore")
    assert (one(tls, "ciamCertPurpose"), values(tls, "ciamSubjectAltName")) == ("tls-server", ("sso.example.test",))


def test_no_secret_is_read():
    d = _record()
    dump = json.dumps([dict(e.attrs) for _, es in read_export(_files(), d, ()).groups for e in es])
    assert "OBF:" not in dump and "not-a-real-password" not in dump


def test_data_stores_are_recorded_and_every_resource_read():
    d = _record()
    imported = read_export(_files(), d, ())
    after = _after(d, imported)
    users = get(after, f"cn=user-directory,{DATA_STORES}")
    assert (one(users, "pingfedStoreType"), one(users, "pingfedConsumer")) == ("LDAP", f"cn=pf-ds-svc,{CONSUMERS}")
    assert {"exported from PingFederate 12.1.4.0",
            "LDAP data store User directory: reaches server ds-1.internal.example.test by its hostname, not a service "
            "name (it changes when servers are replaced or moved)",
            "LDAP data store User directory: no single service name for its hosts, so it reaches the same place from "
            "every environment"} <= set(imported.notices)
    assert not any(n.startswith("not read yet") for n in imported.notices)
    assert not any("ldap.example.test" in n for n in imported.notices)          # a service name: as it should be


def test_importing_the_same_export_again_changes_nothing():
    d = _record()
    after = _after(d, read_export(_files(), d, ()))
    assert not import_changes(after, read_export(_files(), after, ()))


def test_the_adapters_own_render_reads_back_as_it_was():
    d = _record()
    after = _after(d, read_export(_files(), d, ()))
    rendered = admin_api_files(SimpleNamespace(d=after, servers=(), bindings=()))      # an environment binding nothing
    assert rendered and not import_changes(after, read_export(rendered, after, ()))


def test_fingerprints_are_written_as_the_record_writes_them():
    assert fingerprint("1850453c") == "18:50:45:3C" and fingerprint("18:50:45:3C") == "18:50:45:3C"


def test_a_certificate_keeps_the_facts_the_export_doesnt_give():
    d = _record()
    after = _after(d, read_export(_files(), d, ()))
    signing = get(after, f"cn=pf-signing-2025,{CERTIFICATES}")
    assert (one(signing, "ciamSubject"), one(signing, "ciamIssuer"), one(signing, "ciamOwner")) == \
        ("CN=sso.example.test", "self-signed", "cn=platform,ou=owners,dc=ciam-ops")
    bare = {"data.json": json.dumps({"operations": [{"operationType": "SAVE", "resourceType": "/keyPairs/signing",
                                                      "items": [{"id": "signing-2025", "sha256Fingerprint": SIGNING_FP,
                                                                 "expires": "2027-06-30T00:00:00Z"}]}]})}
    again = _after(after, read_export(bare, after, ()))
    assert one(get(again, f"cn=pf-signing-2025,{CERTIFICATES}"), "ciamSubject") == "CN=sso.example.test"
