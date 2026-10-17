"""Google Cloud Certificate Authority Service inventory (gcp/private-ca): the importer reads each CA of the project's
pools into its record CA (named after its certificate's CN; resource name as provider ref; root or subordinate,
state, a Google-managed HSM key's algorithm or the Cloud KMS key version, the parent from subordinateConfig), its CRL
and CA certificate URLs and the pool's OCSP servers, its own templates (the pool's policy alone and with each
template: subject passthrough, EKUs, lifetime; who may request from the pool, template and project IAM) and the
certificates its Enterprise pool keeps (from the PEM; revocation by RFC name); a DevOps pool's inventory is
incomplete. The collector lists only, trims certificates and skips DevOps pools' certificates. Recorded fixtures follow
the v1 REST resources gcloud prints (no live project)."""
import datetime as dt
import importlib.util
import json
import pathlib
import shlex

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from opsdir.connectors.collecting import collect
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, make_entry, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.issued import REVOKED, reconciled
from opsdir.domains.pki.inventory import PRESENT
from opsdir.domains.pki.naming import authority_dn, issued_inventory_dn, template_dn
from opsdir.domains.pki.templates import BROAD, RESTRICTED, UNKNOWN, check_template_risk
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.collect import COLLECTORS, certificate_fields, private_ca_steps
from opsdir_adapter_gcp.private_ca import (PRIVATE_CA_IMPORTER, lifetime_days, names_subject, read_private_ca,
                                          template_facts)
from opsdir_adapter_gcp.private_ca_access import enrollment
import mini_estate
from support import REGISTRY, after_import, build_directory

P, L = "example-aero-ciam-standby", "us-central1"
POOL, DEVPOOL = f"projects/{P}/locations/{L}/caPools/ciam-enterprise", f"projects/{P}/locations/{L}/caPools/ciam-mesh"
ROOT_CA, SUB_CA, MESH_CA = "Example Aero Standby Root CA", "Example Aero Standby Issuing CA", "Example Aero Mesh CA"
ROOT_NAME, SUB_NAME = f"{POOL}/certificateAuthorities/standby-root", f"{POOL}/certificateAuthorities/standby-issuing"
MESH_NAME = f"{DEVPOOL}/certificateAuthorities/mesh"
TEMPLATE = f"projects/{P}/locations/{L}/certificateTemplates/ciam-client"
KMS = f"projects/{P}/locations/{L}/keyRings/pki/cryptoKeys/root/cryptoKeyVersions/1"
SERVER, CLIENT = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"
AT = dt.datetime(2026, 9, 23, 9, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 9, 23)
KEY = ec.generate_private_key(ec.SECP256R1())
OPERATORS = "group:ciam-pki-operators@example-aero.test"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _pem(cn, issuer, serial, ca=False, start="2026-09-01", days=365, usages=(ExtendedKeyUsageOID.SERVER_AUTH,)):
    begin = dt.datetime.fromisoformat(start).replace(tzinfo=dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer)).public_key(KEY.public_key())
         .serial_number(serial).not_valid_before(begin).not_valid_after(begin + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    b = b.add_extension(x509.ExtendedKeyUsage(list(usages)), critical=False) if usages else b
    return b.sign(KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()


ROOT_PEM = _pem(ROOT_CA, ROOT_CA, 0x0A01, ca=True, start="2026-01-01", days=3650, usages=())
SUB_PEM = _pem(SUB_CA, ROOT_CA, 0x0A02, ca=True, start="2026-01-02", days=1825, usages=())
MESH_PEM = _pem(MESH_CA, MESH_CA, 0x0A03, ca=True, start="2026-01-03", days=1825, usages=())
WEB_PEM = _pem("portal.standby.example-aero.test", SUB_CA, 0x7E01)
CLIENT_PEM = _pem("svc-sync", SUB_CA, 0x7E02, usages=(ExtendedKeyUsageOID.CLIENT_AUTH,))


def _ca(name, kind, pem, spec, parent=None, state="ENABLED", urls=True):
    """A CertificateAuthority as gcloud privateca roots/subordinates list prints it (v1 REST shape)."""
    bucket = "privateca-content-example-aero"
    return {"name": name, "type": kind, "tier": "ENTERPRISE", "state": state, "keySpec": spec,
            "pemCaCertificates": [pem], "lifetime": "315360000s", "createTime": "2026-01-01T00:00:00Z",
            **({"subordinateConfig": {"certificateAuthority": parent}} if parent else {}),
            **({"accessUrls": {"caCertificateAccessUrl": f"http://storage.googleapis.com/{bucket}/{name[-8:]}/ca.crt",
                               "crlAccessUrls": [f"http://storage.googleapis.com/{bucket}/{name[-8:]}/crl.crl"]}}
               if urls else {})}


POOL_DOC = {"name": POOL, "tier": "ENTERPRISE",
            "issuancePolicy": {"maximumLifetime": "31536000s",
                               "baselineValues": {"keyUsage": {"baseKeyUsage": {"digitalSignature": True},
                                                               "extendedKeyUsage": {"serverAuth": True}},
                                                  "caOptions": {"isCa": False},
                                                  "aiaOcspServers": ["http://ocsp.standby.example-aero.test"]},
                               "identityConstraints": {"allowSubjectPassthrough": False,
                                                       "allowSubjectAltNamesPassthrough": False}},
            "publishingOptions": {"publishCaCert": True, "publishCrl": True, "encodingFormat": "PEM"}}
DEVPOOL_DOC = {"name": DEVPOOL, "tier": "DEVOPS", "issuancePolicy": {}}
TEMPLATE_DOC = {"name": TEMPLATE, "maximumLifetime": "86400s", "description": "CIAM client certificates",
                "predefinedValues": {"keyUsage": {"extendedKeyUsage": {"clientAuth": True}}},
                "identityConstraints": {"allowSubjectPassthrough": True, "allowSubjectAltNamesPassthrough": True}}
CERTS = [{"name": f"{POOL}/certificates/web-1", "issuerCertificateAuthority": SUB_NAME, "pemCertificate": WEB_PEM,
          "subjectMode": "DEFAULT", "createTime": "2026-09-01T00:00:00Z", "pemCsr": "-----BEGIN CERTIFICATE REQUEST--",
          "certificateDescription": {"certFingerprint": {"sha256Hash": "ab"}}},
         {"name": f"{POOL}/certificates/sync-1", "issuerCertificateAuthority": SUB_NAME, "pemCertificate": CLIENT_PEM,
          "certificateTemplate": TEMPLATE, "subjectMode": "DEFAULT", "createTime": "2026-09-01T00:00:00Z",
          "revocationDetails": {"revocationState": "KEY_COMPROMISE",
                                "revocationTime": "2026-09-20T10:00:00.123456789Z"}}]
POOL_IAM = {"version": 1, "etag": "BwY=", "bindings": [{"role": "roles/privateca.certificateRequester",
                                                         "members": [OPERATORS]}]}
TEMPLATE_IAM = {"version": 1, "etag": "BwY=", "bindings": [{"role": "roles/privateca.templateUser",
                                                             "members": ["allAuthenticatedUsers"]}]}
PROJECT_IAM = {"version": 1, "etag": "BwY=", "bindings": [
    {"role": "roles/privateca.certificateRequester",
     "members": ["serviceAccount:sync@example.iam.gserviceaccount.com"]},
    {"role": "roles/owner", "members": ["user:admin@example-aero.test"]}]}


def export(certs=CERTS, drop=()):
    at = lambda pool, name: f"private-ca/{L}/{pool}/{name}"     # noqa: E731
    files = {"private-ca/pools.json": json.dumps([POOL_DOC, DEVPOOL_DOC]),
             "private-ca/project-iam.json": json.dumps(PROJECT_IAM),
             at("ciam-enterprise", "roots.json"): json.dumps([_ca(ROOT_NAME, "SELF_SIGNED", ROOT_PEM,
                                                                  {"cloudKmsKeyVersion": KMS})]),
             at("ciam-enterprise", "subordinates.json"): json.dumps([_ca(SUB_NAME, "SUBORDINATE", SUB_PEM,
                                                                         {"algorithm": "EC_P256_SHA256"},
                                                                         ROOT_NAME)]),
             at("ciam-enterprise", "iam.json"): json.dumps(POOL_IAM),
             at("ciam-enterprise", "certificates.json"): certificate_fields(json.dumps(certs)),
             at("ciam-mesh", "roots.json"): json.dumps([_ca(MESH_NAME, "SELF_SIGNED", MESH_PEM,
                                                            {"algorithm": "EC_P256_SHA256"}, urls=False)]),
             at("ciam-mesh", "subordinates.json"): "[]",
             at("ciam-mesh", "iam.json"): json.dumps({"etag": "ACAB"}),
             f"private-ca/{L}/templates.json": json.dumps([TEMPLATE_DOC]),
             f"private-ca/{L}/templates/ciam-client/iam.json": json.dumps(TEMPLATE_IAM)}
    return {p: t for p, t in files.items() if p not in drop}


def _record(*certificates):
    head = ("dn: ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: owners\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *certificates)))))


def _imported(d=None, files=None):
    d = d if d is not None else _record()
    return after_import(d, read_private_ca(files if files is not None else export(), d, (), AT))


def test_registered_with_its_collector():
    assert "private-ca" in [i.name for i in ADAPTER.importers] and PRIVATE_CA_IMPORTER.name == "private-ca"
    assert ("private-ca", "environment") in [(c.importer, c.scope) for c in ADAPTER.collectors]


def test_the_cas_with_what_google_says_of_them():
    d = _imported()
    root, sub, mesh = (get(d, authority_dn(n)) for n in (ROOT_CA, SUB_CA, MESH_CA))
    assert one(sub, "ciamProviderRef") == SUB_NAME
    assert (one(root, "ciamCaType"), one(root, "ciamCaKeyStorage"), one(root, "ciamCaKeyRef"),
            one(root, "ciamCaKeyAlgorithm")) == ("root", "Cloud KMS key", KMS, None)
    assert (one(sub, "ciamCaType"), one(sub, "ciamCaState"), one(sub, "ciamCaKeyAlgorithm"),
            one(sub, "ciamCaKeyStorage"), one(sub, "ciamParentAuthority")) == (
        "subordinate", "active", "EC_P256_SHA256", "Google-managed HSM", authority_dn(ROOT_CA))
    ends = {one(e, "cn"): one(e, "ciamEndpointUrl") for e in d.entries.values() if e.dn.endswith(sub.dn)
            and e.dn != sub.dn}
    assert set(ends) == {"crl-1", "ocsp-1", "ca-issuers-1"} and ends["ocsp-1"] == "http://ocsp.standby.example-aero.test"
    assert values(sub, "ciamTemplateName") == (f"{SUB_CA}/ciam-enterprise", f"{SUB_CA}/ciam-enterprise/ciam-client")
    assert one(mesh, "ciamCaState") == "active"


def test_the_pools_certificates_are_the_inventory():
    d = _imported()
    inv = get(d, issued_inventory_dn(SUB_CA))
    assert one(inv, "ciamInventoryState") == "complete"
    web, sync = get(d, f"cn=7e01,{inv.dn}"), get(d, f"cn=7e02,{inv.dn}")
    assert (one(web, "ciamSubject"), one(web, "ciamTemplateName"), one(web, "ciamRequester")) == (
        "CN=portal.standby.example-aero.test", f"{SUB_CA}/ciam-enterprise", None)
    assert one(web, "ciamFingerprint") and one(web, "ciamRevocationReason") is None
    assert (one(sync, "ciamTemplateName"), one(sync, "ciamRevocationReason"), one(sync, "ciamRevokedAt")) == (
        f"{SUB_CA}/ciam-enterprise/ciam-client", "keyCompromise", "20260920100000Z")
    assert one(get(d, issued_inventory_dn(ROOT_CA)), "ciamInventoryState") == "complete"
    mesh = get(d, issued_inventory_dn(MESH_CA))
    assert one(mesh, "ciamInventoryState") == "incomplete" and "DevOps" in one(mesh, "ciamInventoryProblem")
    unread = _imported(files=export(drop=(f"private-ca/{L}/ciam-enterprise/certificates.json",)))
    assert one(get(unread, issued_inventory_dn(SUB_CA)), "ciamInventoryState") == "incomplete"


def test_templates_combine_the_pool_and_the_template():
    d = _imported()
    plain, client = (get(d, template_dn(n)) for n in (f"{SUB_CA}/ciam-enterprise",
                                                      f"{SUB_CA}/ciam-enterprise/ciam-client"))
    assert (one(plain, "ciamSubjectFromRequest"), values(plain, "ciamExtendedKeyUsage"),
            one(plain, "ciamMaxValidityDays")) == ("FALSE", (SERVER,), "365")
    assert (one(client, "ciamSubjectFromRequest"), values(client, "ciamExtendedKeyUsage"),
            one(client, "ciamMaxValidityDays"), one(client, "description")) == (
        "FALSE", (SERVER, CLIENT), "1", "CIAM client certificates")
    assert one(client, "ciamTemplateAuthority") == authority_dn(SUB_CA)
    assert (values(plain, "ciamEnrollee"), one(plain, "ciamEnrollmentScope")) == (
        (OPERATORS, "serviceAccount:sync@example.iam.gserviceaccount.com"), RESTRICTED)
    # every authenticated account may use the template: whoever may request from the pool may use it
    assert one(client, "ciamEnrollmentScope") == RESTRICTED


def test_a_passthrough_pool_with_a_broad_template_is_an_action():
    open_pool = {**POOL_DOC, "issuancePolicy": {**POOL_DOC["issuancePolicy"], "identityConstraints": {
        "allowSubjectPassthrough": True, "allowSubjectAltNamesPassthrough": True}}}
    files = export()
    files["private-ca/pools.json"] = json.dumps([open_pool, DEVPOOL_DOC])
    files[f"private-ca/{L}/ciam-enterprise/iam.json"] = json.dumps({"bindings": [
        {"role": "roles/privateca.certificateRequester", "members": ["domain:example-aero.test"]}]})
    d = _imported(files=files)
    client = get(d, template_dn(f"{SUB_CA}/ciam-enterprise/ciam-client"))
    assert (one(client, "ciamSubjectFromRequest"), one(client, "ciamEnrollmentScope")) == ("TRUE", BROAD)
    found = check_template_risk(PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), None, AS_OF,
                                            {}, {}, ()))
    assert any(f"`{SUB_CA}/ciam-enterprise/ciam-client`" in a[1] and "domain:example-aero.test" in a[1]
               for a in found.actions)


def test_record_certificates_reconcile():
    def recorded(cn, pem):
        from opsdir_adapter_x509.certificates import certificate_facts
        f = certificate_facts(pem)
        return (f"dn: cn={cn},ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
                f"objectClass: ciamCertificate\ncn: {cn}\nciamFingerprint: {f['sha256']}\n"
                f"ciamNotAfter: {f['not_after']}\nciamNotBefore: {f['not_before']}\nciamCertPurpose: tls-server\n"
                f"ciamSubject: {f['subject']}\nciamIssuer: CN={SUB_CA}\n")
    d = _imported(_record(recorded("portal-standby", WEB_PEM), recorded("sync-client", CLIENT_PEM)))
    assert {r.cert.attrs["cn"][0]: r.state for r in reconciled(d, AS_OF)} == {"portal-standby": PRESENT,
                                                                              "sync-client": REVOKED}


def test_policy_pieces():
    assert names_subject() and names_subject(None) and not names_subject({"allowSubjectPassthrough": False})
    assert lifetime_days("2592000s", None, "86401s") == 2 and lifetime_days(None) is None
    passthrough = {**POOL_DOC, "issuancePolicy": {**POOL_DOC["issuancePolicy"], "passthroughExtensions": {
        "knownExtensions": ["EXTENDED_KEY_USAGE"]}}}
    assert template_facts(passthrough)[1] == ()
    assert enrollment(POOL_IAM, None, None, False)[1:] == (UNKNOWN, "the project's IAM policy wasn't read")
    conditional = {"bindings": [{"role": "roles/privateca.certificateRequester", "members": ["user:a@x.test"],
                                 "condition": {"expression": "true", "title": "t"}}]}
    assert enrollment(conditional, None, {}, False)[1] == UNKNOWN
    custom = {"bindings": [{"role": f"projects/{P}/roles/pkiIssuer", "members": ["user:b@x.test"]}]}
    assert enrollment(custom, None, {}, False)[1] == UNKNOWN
    assert enrollment({"bindings": [{"role": "roles/privateca.admin", "members": ["allUsers"]}]}, None, {},
                      False)[:2] == (("allUsers",), BROAD)


def _model():
    spec = importlib.util.spec_from_file_location("gcp_cli_fixtures_pca",
                                                  pathlib.Path(__file__).with_name("test_gcp_cli.py"))
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    d = build_directory(REGISTRY, tuple(parse(cli.RECORDS)))
    dn = "cloud=gcp,ou=environments,dc=ciam-ops"
    d = d._replace(entries={**d.entries, dn: make_entry(dn, (*d.entries[dn].classes, "ciamCloudAccount"),
                                                        {**d.entries[dn].attrs, "ciamAccountRef": (P,)})})
    return env_model(d, "gcp/prod")


def _answer(argv):
    files = export(certs=CERTS)
    words = [a for a in argv[1:] if not a.startswith("-")]
    flags = dict(a[2:].split("=", 1) for a in argv if a.startswith("--") and "=" in a)
    if words[:2] == ["privateca", "pools"] and words[2] == "list":
        return files["private-ca/pools.json"]
    if words[:2] == ["projects", "get-iam-policy"]:
        return files["private-ca/project-iam.json"]
    if words[1] in ("roots", "subordinates"):
        return files[f"private-ca/{flags['location']}/{flags['pool']}/{words[1]}.json"]
    if words[1:3] == ["pools", "get-iam-policy"]:
        return files[f"private-ca/{flags['location']}/{words[3]}/iam.json"]
    if words[1] == "certificates":
        return json.dumps(CERTS)
    if words[1:3] == ["templates", "list"]:
        return files[f"private-ca/{flags['location']}/templates.json"]
    return files[f"private-ca/{flags['location']}/templates/{words[3]}/iam.json"]


def test_the_collector_lists_trims_and_skips_devops_certificates():
    m = _model()
    c = collect("gcp/private-ca", COLLECTORS[-1], m.d, m, lambda call: (_answer(call.argv), None))
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    assert {" ".join(a[1:4] if a[1] == "privateca" else a[1:3]) for a in ran} >= {
        "privateca pools list", "projects get-iam-policy", "privateca roots list", "privateca certificates list",
        "privateca templates list", "privateca templates get-iam-policy", "privateca pools get-iam-policy"}
    assert not any(a[1] == "privateca" and a[2] == "certificates" and "--issuer-pool=ciam-mesh" in a for a in ran)
    assert all(f"--project={P}" in a for a in ran if a[1] == "privateca")
    saved = json.loads(c.files[f"private-ca/{L}/ciam-enterprise/certificates.json"])
    assert "pemCsr" not in saved[0] and "certificateDescription" not in saved[0] and saved[0]["pemCertificate"]
    assert private_ca_steps(m.d, m._replace(cloud=make_entry(m.cloud.dn, m.cloud.classes, {})), {}, {}) == ()


def test_a_deleted_ca_says_when_google_purges_it():
    sub = {**_ca(SUB_NAME, "SUBORDINATE", SUB_PEM, {"algorithm": "EC_P256_SHA256"}, ROOT_NAME, state="DELETED"),
           "deleteTime": "2026-09-20T10:00:00Z", "expireTime": "2026-10-20T10:00:00Z"}
    files = {**export(), f"private-ca/{L}/ciam-enterprise/subordinates.json": json.dumps([sub])}
    ca = get(_imported(files=files), authority_dn(SUB_CA))
    assert (one(ca, "ciamCaState"), one(ca, "ciamCaRestorableUntil")) == ("deleted", "20261020100000Z")
    assert one(get(_imported(), authority_dn(SUB_CA)), "ciamCaRestorableUntil") is None
