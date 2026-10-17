"""AWS Private CA inventory (aws/private-ca): the importer reads each owned CA into its record CA (named after its
certificate's CN; ARN as provider ref; root or subordinate, state, key algorithm and storage, the parent CA), its CRL
and OCSP endpoints (a partitioned CRL kept as a template), the templates its newest audit report shows as its own (the
family's EKUs, subject from the request; who may request from the account's IAM, the CA's resource policy and ACM)
and that report's certificates (serial, template, ACM as requester, revocation by RFC name); the inventory is
complete only for a report less than a day older than the read, incomplete without one, naming the command that
creates it. The enrollment reader judges Action/NotAction, Resource/NotResource, template conditions and denies; what
it can't judge is unknown. The collector reads only (no report is ever created) and reads reports only from a named
bucket. Recorded fixtures follow the AWS CLI reference's documented shapes (no live account)."""
import datetime as dt
import importlib.util
import json
import pathlib
import shlex

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from opsdir.connectors.collecting import collect
from opsdir.core.contract import PlanContext
from opsdir.core.directory import get, make_entry, one, values
from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.inventory import PRESENT
from opsdir.domains.pki.issued import REVOKED, authority_rows, reconciled
from opsdir.domains.pki.naming import authority_dn, issued_inventory_dn, template_dn
from opsdir.domains.pki.templates import BROAD, RESTRICTED, UNKNOWN, check_template_risk
from opsdir_adapter_aws.adapter import ADAPTER
from opsdir_adapter_aws.collect import COLLECTORS, private_ca_problems, private_ca_steps
from opsdir_adapter_aws.private_ca import (PRIVATE_CA_IMPORTER, endpoints, read_private_ca, template_name,
                                          template_usages)
from opsdir_adapter_aws.private_ca_access import access, enrollment, statement_grant
import mini_estate
from support import after_import

ACCOUNT, OTHER = "111122223333", "444455556666"
ROOT_ID, SUB_ID = "11111111-aaaa-4bbb-8ccc-000000000001", "22222222-aaaa-4bbb-8ccc-000000000002"
ROOT_ARN = f"arn:aws:acm-pca:us-east-1:{ACCOUNT}:certificate-authority/{ROOT_ID}"
SUB_ARN = f"arn:aws:acm-pca:us-east-1:{ACCOUNT}:certificate-authority/{SUB_ID}"
ROOT_CA, SUB_CA = "Example Aero Cloud Root CA", "Example Aero Cloud Issuing CA"
END_ENTITY, CLIENT_T = "EndEntityCertificate/V1", "EndEntityClientAuthCertificate_APIPassthrough/V1"
SERVER, CLIENT = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"
AT = dt.datetime(2026, 9, 23, 9, 0, tzinfo=dt.timezone.utc)
AS_OF = dt.date(2026, 9, 23)
KEY = ec.generate_private_key(ec.SECP384R1())
OPERATOR = f"arn:aws:iam::{ACCOUNT}:role/ciam-pki-operator"
WORKLOAD = f"arn:aws:iam::{ACCOUNT}:role/ciam-workload"


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _ca_pem(cn, issuer):
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer)).public_key(KEY.public_key())
         .serial_number(0x1001 if cn == issuer else 0x1002)
         .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
         .not_valid_after(dt.datetime(2036, 1, 1, tzinfo=dt.timezone.utc))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True))
    return b.sign(KEY, hashes.SHA384()).public_bytes(serialization.Encoding.PEM).decode()


def _ca(arn, kind, cn, crl=None, ocsp=None, status="ACTIVE"):
    """One CertificateAuthority as list-certificate-authorities answers it (AWS CLI reference shape)."""
    return {"Arn": arn, "OwnerAccount": ACCOUNT, "CreatedAt": "2026-01-01T00:00:00+00:00", "Type": kind,
            "Serial": "1001", "Status": status, "NotBefore": "2026-01-01T00:00:00+00:00",
            "NotAfter": "2036-01-01T00:00:00+00:00", "KeyStorageSecurityStandard": "FIPS_140_2_LEVEL_3_OR_HIGHER",
            "UsageMode": "GENERAL_PURPOSE",
            "CertificateAuthorityConfiguration": {"KeyAlgorithm": "EC_secp384r1",
                                                  "SigningAlgorithm": "SHA384WITHECDSA",
                                                  "Subject": {"CommonName": cn, "Organization": "Example Aero"}},
            "RevocationConfiguration": {"CrlConfiguration": crl or {"Enabled": False},
                                        "OcspConfiguration": ocsp or {"Enabled": False}}}


SUB_CRL = {"Enabled": True, "ExpirationInDays": 7, "S3BucketName": "example-aero-pki-crl",
           "S3ObjectAcl": "BUCKET_OWNER_FULL_CONTROL", "CrlType": "COMPLETE"}
SUB_OCSP = {"Enabled": True, "OcspCustomCname": "ocsp.pki.example-aero.test"}
REPORT = [
    {"awsAccountId": ACCOUNT, "requestedByServicePrincipal": "acm.amazonaws.com",
     "certificateArn": f"{SUB_ARN}/certificate/aa01", "serial": "5a:01", "subject": "CN=portal.example-aero.test",
     "notBefore": "2026-09-01T00:00:00+0000", "notAfter": "2027-09-01T00:00:00+0000",
     "issuedAt": "2026-09-01T00:00:05+0000", "templateArn": f"arn:aws:acm-pca:::template/{END_ENTITY}"},
    {"awsAccountId": ACCOUNT, "certificateArn": f"{SUB_ARN}/certificate/aa02", "serial": "5a:02",
     "subject": "CN=svc-batch", "notBefore": "2026-09-05T00:00:00+0000", "notAfter": "2026-12-05T00:00:00+0000",
     "issuedAt": "2026-09-05T00:00:05+0000", "revokedAt": "2026-09-20T10:00:00+0000",
     "revocationReason": "KEY_COMPROMISE", "templateArn": f"arn:aws:acm-pca:::template/{CLIENT_T}"}]
IAM = {"UserDetailList": [], "GroupDetailList": [],
       "RoleDetailList": [
           {"Arn": OPERATOR, "RolePolicyList": [], "AttachedManagedPolicies": [
               {"PolicyName": "ciam-pki-issue", "PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/ciam-pki-issue"}]},
           {"Arn": WORKLOAD, "RolePolicyList": [{"PolicyName": "acm", "PolicyDocument": {
               "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "acm:RequestCertificate",
                                                        "Resource": "*"}]}}], "AttachedManagedPolicies": []}],
       "Policies": [{"Arn": f"arn:aws:iam::{ACCOUNT}:policy/ciam-pki-issue", "PolicyVersionList": [
           {"IsDefaultVersion": True, "Document": {"Version": "2012-10-17", "Statement": [
               {"Effect": "Allow", "Action": "acm-pca:IssueCertificate", "Resource": SUB_ARN,
                "Condition": {"ArnLike": {"acm-pca:TemplateArn": ["arn:aws:acm-pca:::template/EndEntity*"]}}}]}}]}]}
SHARE = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": OTHER},
                                                 "Action": ["acm-pca:IssueCertificate", "acm-pca:GetCertificate"],
                                                 "Resource": SUB_ARN, "Condition": {"StringEquals": {
                                                     "acm-pca:TemplateArn": f"arn:aws:acm-pca:::template/{CLIENT_T}"
                                                 }}}]}
PERMISSIONS = {"Permissions": [{"CertificateAuthorityArn": SUB_ARN, "Principal": "acm.amazonaws.com",
                                "SourceAccount": ACCOUNT, "Actions": ["IssueCertificate", "GetCertificate",
                                                                      "ListPermissions"]}]}
ROOT_PEM, SUB_PEM = _ca_pem(ROOT_CA, ROOT_CA), _ca_pem(SUB_CA, ROOT_CA)


def export(report=REPORT, reports_at="2026-09-23T08:30:00+00:00", sub_crl=SUB_CRL, drop=()):
    """The export as `opsdir collect` saves it."""
    at = lambda ca, name: f"private-ca/{ca}/{name}"       # noqa: E731
    files = {"private-ca/cas.json": json.dumps({"CertificateAuthorities": [
                 _ca(ROOT_ARN, "ROOT", ROOT_CA), _ca(SUB_ARN, "SUBORDINATE", SUB_CA, sub_crl, SUB_OCSP)]}),
             "private-ca/shared-cas.json": json.dumps({"CertificateAuthorities": []}),
             "private-ca/iam.json": json.dumps(IAM),
             at(ROOT_ID, "certificate.json"): json.dumps({"Certificate": ROOT_PEM}),
             at(SUB_ID, "certificate.json"): json.dumps({"Certificate": SUB_PEM, "CertificateChain": ROOT_PEM}),
             at(SUB_ID, "policy.json"): json.dumps({"Policy": json.dumps(SHARE)}),
             at(ROOT_ID, "permissions.json"): json.dumps({"Permissions": []}),
             at(SUB_ID, "permissions.json"): json.dumps(PERMISSIONS),
             at(ROOT_ID, "audit-reports.json"): "null",
             at(SUB_ID, "audit-reports.json"): json.dumps([{"Key": f"audit-report/{SUB_ID}/r-1.json",
                                                            "LastModified": reports_at}]),
             at(SUB_ID, "audit-report.json"): json.dumps(report)}
    return {p: t for p, t in files.items() if p not in drop}


def _record(*certificates):
    head = ("dn: ou=owners,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: owners\n",
            "dn: ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\nobjectClass: organizationalUnit\n"
            "ou: certificates\n")
    return mini_estate.directory(tuple(parse("\n".join((*head, *certificates)))))


def _imported(d=None, files=None, at=AT):
    d = d if d is not None else _record()
    return after_import(d, read_private_ca(files if files is not None else export(), d, (), at))


def test_registered_with_its_collector():
    assert PRIVATE_CA_IMPORTER.name in [i.name for i in ADAPTER.importers]
    assert "private-ca" in [c.importer for c in ADAPTER.collectors] and COLLECTORS[-1].scope == "environment"


def test_the_cas_with_what_aws_says_of_them():
    d = _imported()
    root, sub = get(d, authority_dn(ROOT_CA)), get(d, authority_dn(SUB_CA))
    assert one(sub, "ciamProviderRef") == SUB_ARN
    assert (one(root, "ciamCaType"), one(root, "ciamCaState"), one(root, "ciamParentAuthority")) == ("root", "active",
                                                                                                     None)
    assert (one(sub, "ciamCaType"), one(sub, "ciamCaKeyAlgorithm"), one(sub, "ciamCaKeyStorage"),
            one(sub, "ciamParentAuthority")) == ("subordinate", "EC_secp384r1", "FIPS_140_2_LEVEL_3_OR_HIGHER",
                                                 authority_dn(ROOT_CA))
    assert values(sub, "ciamTemplateName") == (f"{SUB_CA}/{END_ENTITY}", f"{SUB_CA}/{CLIENT_T}")
    ends = {one(e, "cn"): one(e, "ciamEndpointUrl") for e in d.entries.values() if e.dn.endswith(sub.dn)
            and e.dn != sub.dn}
    assert ends == {"crl-1": f"http://example-aero-pki-crl.s3.us-east-1.amazonaws.com/crl/{SUB_ID}.crl",
                    "ocsp-1": "http://ocsp.pki.example-aero.test"}
    rows = {r[0]: r for r in authority_rows(d)}
    assert rows[SUB_CA][2:5] == ("subordinate active", "EC_secp384r1, FIPS_140_2_LEVEL_3_OR_HIGHER", ROOT_CA)


def test_the_audit_report_is_the_inventory():
    d = _imported()
    inv = get(d, issued_inventory_dn(SUB_CA))
    assert (one(inv, "ciamInventoryState"), one(inv, "ciamInventoryAt")) == ("complete", "20260923083000Z")
    acm, batch = get(d, f"cn=5a01,{inv.dn}"), get(d, f"cn=5a02,{inv.dn}")
    assert (one(acm, "ciamSerialNumber"), one(acm, "ciamSubject"), one(acm, "ciamNotAfter"),
            one(acm, "ciamTemplateName"), one(acm, "ciamRequester"), one(acm, "ciamFingerprint")) == (
        "5a01", "CN=portal.example-aero.test", "20270901000000Z", f"{SUB_CA}/{END_ENTITY}", "acm.amazonaws.com", None)
    assert (one(batch, "ciamRevocationReason"), one(batch, "ciamRevokedAt")) == ("keyCompromise", "20260920100000Z")
    root_inv = get(d, issued_inventory_dn(ROOT_CA))
    assert one(root_inv, "ciamInventoryState") == "incomplete"
    assert "create-certificate-authority-audit-report" in one(root_inv, "ciamInventoryProblem")


def test_a_stale_or_missing_report_leaves_it_incomplete():
    d = _imported(files=export(reports_at="2026-09-20T08:30:00+00:00"))
    inv = get(d, issued_inventory_dn(SUB_CA))
    assert one(inv, "ciamInventoryState") == "incomplete"
    assert "from 2026-09-20 08:30Z, 3 day(s) before the read" in one(inv, "ciamInventoryProblem")
    unnamed = export(drop=(f"private-ca/{SUB_ID}/audit-reports.json", f"private-ca/{SUB_ID}/audit-report.json"))
    d = _imported(files=unnamed)
    assert "ciamSourceRef s3://<bucket>" in one(get(d, issued_inventory_dn(SUB_CA)), "ciamInventoryProblem")
    assert get(d, template_dn(f"{SUB_CA}/{END_ENTITY}")) is None


def test_templates_are_the_cas_own_with_who_may_request():
    d = _imported()
    ee, client = get(d, template_dn(f"{SUB_CA}/{END_ENTITY}")), get(d, template_dn(f"{SUB_CA}/{CLIENT_T}"))
    assert one(ee, "ciamTemplateAuthority") == authority_dn(SUB_CA)
    assert values(ee, "ciamExtendedKeyUsage") == (SERVER, CLIENT) and values(client, "ciamExtendedKeyUsage") == (
        CLIENT,)
    assert (one(ee, "ciamSubjectFromRequest"), one(ee, "ciamApprovalRequired"),
            one(ee, "ciamRequiredSignatures"), one(ee, "ciamMaxValidityDays")) == ("TRUE", "FALSE", "0", None)
    assert (values(ee, "ciamEnrollee"), one(ee, "ciamEnrollmentScope")) == (
        (OPERATOR, f"{WORKLOAD} (through ACM)"), RESTRICTED)
    # EndEntity* takes in the client template too; the other account is broad
    assert (values(client, "ciamEnrollee"), one(client, "ciamEnrollmentScope")) == ((OPERATOR, OTHER), BROAD)


def test_the_shared_client_template_is_an_action():
    d = _imported()
    m = env_model(d, "alpha/prod")
    found = check_template_risk(PlanContext(d, m, env_model(d, "beta/prod"), None, AS_OF, {}, {}, ()))
    (action,) = found.actions
    assert f"`{SUB_CA}/{CLIENT_T}`" in action[1] and OTHER in action[1]


def test_record_certificates_reconcile_by_serial():
    cert = ("dn: cn=portal-tls,ou=certificates,dc=ciam-ops\nchangetype: add\nobjectClass: top\n"
            "objectClass: ciamCertificate\ncn: portal-tls\nciamSerialNumber: 5a01\nciamNotAfter: 20270901000000Z\n"
            "ciamNotBefore: 20260901000000Z\nciamCertPurpose: tls-server\nciamSubject: CN=portal.example-aero.test\n"
            f"ciamIssuer: CN={SUB_CA}\n")
    batch = cert.replace("portal-tls", "batch-client").replace("5a01", "5a02").replace(
        "CN=portal.example-aero.test", "CN=svc-batch").replace("20270901000000Z", "20261205000000Z")
    d = _imported(_record(cert, batch))
    assert {r.cert.attrs["cn"][0]: r.state for r in reconciled(d, AS_OF)} == {"portal-tls": PRESENT,
                                                                              "batch-client": REVOKED}


def test_endpoint_forms():
    partitioned = {**SUB_CRL, "CrlType": "PARTITIONED", "CustomCname": "crl.pki.example-aero.test",
                   "CustomPath": "/partitions/"}
    (crl,) = endpoints({"Arn": SUB_ARN, "RevocationConfiguration": {"CrlConfiguration": partitioned}}, "us-east-1")
    assert crl == ("crl", 1, "http://crl.pki.example-aero.test/partitions/{partition}.crl",
                   "http://crl.pki.example-aero.test/partitions/{partition}.crl")
    omitted = {**SUB_CRL, "CrlDistributionPointExtensionConfiguration": {"OmitExtension": True}}
    assert endpoints({"Arn": SUB_ARN, "RevocationConfiguration": {"CrlConfiguration": omitted,
                                                                  "OcspConfiguration": {"Enabled": True}}},
                     "us-gov-west-1") == (("ocsp", 1, "http://ocsp.acm-pca.us-gov-west-1.amazonaws.com", None),)
    gov = export()
    gov["private-ca/cas.json"] = gov["private-ca/cas.json"].replace("us-east-1", "us-gov-west-1").replace(
        "arn:aws:", "arn:aws-us-gov:")
    notices = read_private_ca({k.replace("us-east-1", "us-gov-west-1"): v for k, v in gov.items()}, _record(), (),
                              AT).notices
    assert any("GovCloud (US)" in n for n in notices)


def test_template_names_and_families():
    assert template_name(f"arn:aws-us-gov:acm-pca:::template/{CLIENT_T}") == CLIENT_T
    assert template_usages(CLIENT_T) == (CLIENT,) and template_usages("BlankEndEntityCertificate_APIPassthrough/V1") \
        == () and template_usages("SubordinateCACertificate_PathLen0/V1") == ()


def test_enrollment_reads_grants_literally():
    t = f"arn:aws:acm-pca:::template/{END_ENTITY}"
    allow = {"Statement": [{"Effect": "Allow", "Action": "acm-pca:*", "Resource": "*"}]}
    assert access((allow,), "acm-pca:IssueCertificate", SUB_ARN, t) == "yes"
    not_action = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
    assert access((not_action,), "acm-pca:IssueCertificate", SUB_ARN, t) == "yes"
    denied = {"Statement": [*allow["Statement"], {"Effect": "Deny", "Action": "acm-pca:Issue*",
                                                  "NotResource": ROOT_ARN}]}
    assert access((denied,), "acm-pca:IssueCertificate", SUB_ARN, t) == "no"
    other = {"Statement": [{"Effect": "Allow", "Action": "acm-pca:IssueCertificate", "Resource": "*",
                            "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}]}
    assert access((other,), "acm-pca:IssueCertificate", SUB_ARN, t) == "unknown"
    assert access((None,), "acm-pca:IssueCertificate", SUB_ARN, t) == "unknown"
    assert statement_grant({"Effect": "Allow", "Action": "acm-pca:IssueCertificate", "Resource": ROOT_ARN},
                           "acm-pca:IssueCertificate", SUB_ARN) is None
    except_client = {"Effect": "Allow", "Action": "acm-pca:IssueCertificate", "Resource": "*", "Condition": {
        "ArnNotLike": {"acm-pca:TemplateArn": "*ClientAuth*"}}}
    assert access(({"Statement": [except_client]},), "acm-pca:IssueCertificate", SUB_ARN,
                  f"arn:aws:acm-pca:::template/{CLIENT_T}") == "no"
    assert enrollment(None, None, None, SUB_ARN, ACCOUNT, t, False)[1] == UNKNOWN
    star = {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "acm-pca:IssueCertificate",
                           "Resource": SUB_ARN}]}
    assert enrollment({}, json.dumps(star), None, SUB_ARN, ACCOUNT, t, False)[:2] == (("*",), BROAD)


def _model(*sources):
    cli = importlib.util.spec_from_file_location("aws_cli_fixtures_pca",
                                                 pathlib.Path(__file__).with_name("test_aws_cli.py"))
    module = importlib.util.module_from_spec(cli)
    cli.loader.exec_module(module)
    d = module._record()
    dn = "cloud=main,ou=environments,dc=ciam-ops"
    d = d._replace(entries={**d.entries, dn.lower(): make_entry(dn, (*d.entries[dn.lower()].classes,
                                                                      "ciamCloudAccount"),
                                                                {**d.entries[dn.lower()].attrs,
                                                                 "ciamAccountRef": (ACCOUNT,)})})
    m = env_model(d, "main/prod")
    return m._replace(bindings=(*m.bindings, *(
        make_entry(f"cn=pca-{n},ou=bindings,env=prod,cloud=main,ou=environments,dc=ciam-ops",
                   ("top", "ciamCollectionSource"),
                   {"cn": (f"pca-{n}",), "ciamBindingRole": (f"collect-pca-{n}",),
                    "ciamImporter": ("aws/private-ca",), "ciamSourceRef": (ref,)}) for n, ref in enumerate(sources))))


def _answer(argv):
    """What the AWS CLI prints for a call of the collector, from the export above."""
    files, op = export(), tuple(argv[1:3])
    arg = dict(zip(argv[3::1], argv[4::1]))
    ca = (arg.get("--certificate-authority-arn") or arg.get("--resource-arn") or "").rsplit("/", 1)[-1]
    by_op = {("acm-pca", "get-certificate-authority-certificate"): "certificate.json",
             ("acm-pca", "get-policy"): "policy.json", ("acm-pca", "list-permissions"): "permissions.json"}
    if op == ("acm-pca", "list-certificate-authorities"):
        return files["private-ca/cas.json" if arg["--resource-owner"] == "SELF" else "private-ca/shared-cas.json"]
    if op == ("iam", "get-account-authorization-details"):
        return files["private-ca/iam.json"]
    if op == ("s3api", "list-objects-v2"):
        return files.get(f"private-ca/{arg['--prefix'].split('/')[1]}/audit-reports.json")
    if op[0] == "s3":
        return files[f"private-ca/{argv[3].split('/')[4]}/audit-report.json"]
    return files.get(f"private-ca/{ca}/{by_op[op]}")


def _run(call):
    out = _answer(call.argv)
    return (out, None) if out is not None else (None, None)


def test_the_collector_only_reads_and_reads_reports_from_the_named_bucket():
    m = _model("s3://example-aero-pki-audit")
    assert private_ca_problems(m.d, m, {}) == ()
    c = collect("aws/private-ca", COLLECTORS[-1], m.d, m, _run)
    assert c.problems == ()
    ran = [shlex.split(x.provenance) for x in c.calls]
    ops = {tuple(a[1:3]) for a in ran}
    assert ops == {("acm-pca", "list-certificate-authorities"), ("iam", "get-account-authorization-details"),
                   ("acm-pca", "get-certificate-authority-certificate"), ("acm-pca", "get-policy"),
                   ("acm-pca", "list-permissions"), ("s3api", "list-objects-v2"), ("s3", "cp")}
    assert not any("create" in a[2] for a in ran)
    assert ["s3", "cp", f"s3://example-aero-pki-audit/audit-report/{SUB_ID}/r-1.json", "-"] in [a[1:5] for a in ran]
    assert set(c.files) >= {"private-ca/cas.json", f"private-ca/{SUB_ID}/audit-report.json"}
    without = collect("aws/private-ca", COLLECTORS[-1], m.d, _model(), _run)
    assert not any(a for a in without.calls if " s3" in a.provenance)


def test_collector_problems():
    m = _model("https://example.test", "s3://a")
    assert private_ca_problems(m.d, m, {}) == (
        "aws/private-ca collection source https://example.test: not a bucket (s3://<the audit-report bucket>)",
        "more than one aws/private-ca collection source: name the one audit-report bucket")
    assert private_ca_steps(m.d, _model(), {}, {})[0][0] == "private-ca/cas.json"


def test_a_deleted_ca_says_until_when_it_can_be_restored():
    files = export()
    cas = json.loads(files["private-ca/cas.json"])
    cas["CertificateAuthorities"][1] |= {"Status": "DELETED", "RestorableUntil": "2026-10-20T18:00:00+00:00"}
    d = _imported(files={**files, "private-ca/cas.json": json.dumps(cas)})
    sub = get(d, authority_dn(SUB_CA))
    assert (one(sub, "ciamCaState"), one(sub, "ciamCaRestorableUntil")) == ("deleted", "20261020180000Z")
    assert one(get(_imported(), authority_dn(SUB_CA)), "ciamCaRestorableUntil") is None
