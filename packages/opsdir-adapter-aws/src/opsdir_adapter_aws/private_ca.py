"""AWS Private CA inventory (the importer `aws/private-ca`): each CA the account owns in the region, its revocation
endpoints, the AWS templates it issued from as its own templates, and the certificates its newest audit report lists,
read into the core pki domain's records (domains.pki.issued), metadata only. Pure.

The export holds the AWS CLI's answers as `opsdir collect` saves them (collect.py, private_ca_steps):
  private-ca/cas.json                       list-certificate-authorities --resource-owner SELF
  private-ca/shared-cas.json                list-certificate-authorities --resource-owner OTHER_ACCOUNTS (named only:
                                            their owner holds their audit reports)
  private-ca/iam.json                       iam get-account-authorization-details, projected to the policies
  private-ca/<CA id>/certificate.json       get-certificate-authority-certificate (public PEM)
  private-ca/<CA id>/policy.json            get-policy (the CA's resource policy; absent when it has none)
  private-ca/<CA id>/permissions.json       list-permissions (ACM's)
  private-ca/<CA id>/audit-reports.json     s3api list-objects-v2 of audit-report/<CA id>/ in the report bucket
                                            (the .json reports' Key and LastModified)
  private-ca/<CA id>/audit-report.json      the newest of them (s3 cp)
A CA is named after its certificate's subject common name (else its configured subject's, else its id);
ciamProviderRef is its ARN. What AWS says of it: root or subordinate, its state (CREATING and PENDING_CERTIFICATE are
pending; DELETED is restorable until RestorableUntil, ciamCaRestorableUntil), its key algorithm and storage
standard (AWS-managed HSM keys: no key reference), and for a subordinate the CA in the export (else the record) whose
certificate's subject is its certificate's issuer. Its endpoints are what it writes into what it issues: the CRL
distribution point (http://<CustomCname, else bucket.s3.<region>.amazonaws.com>/<CustomPath, else crl>/<CA id>.crl,
unless the extension is omitted; a partitioned CRL's file name is a GUID per partition, kept as a template) and the
OCSP responder (http://<OcspCustomCname, else ocsp.acm-pca.<region>.amazonaws.com>). In GovCloud (US) those
hostnames follow the general patterns AWS documents; nothing documents them separately (named).

The inventory is the newest audit report: AWS has no call listing a CA's certificates, and creating a report is a
write (acm-pca:CreateCertificateAuthorityAuditReport, at most one per 30 minutes): the CA's owner creates them,
`opsdir collect` only reads the newest. The inventory is dated at that report: complete when it is less than a day
older than the read (--at), else incomplete, and incomplete without one, the problem naming the command that creates
it. A report lists every certificate the CA issued, revoked ones included: serial (cn), subject as AWS writes it,
validity, template, ACM as the requester of what ACM issued, revocation time and reason. It holds no certificate:
no fingerprint (a record certificate is found by serial; README Known limits). Each templateArn the report shows is
one of the CA's own templates (cn <CA>/<template name>/V1, ca_templates_groups): the extended key usages AWS fixes
for its family (none fixed for the Blank* and CA templates), the subject always from the request, no approval or
signature, no validity of its own (the CA's bound); who may request from it is private_ca_access's.
"""
import datetime as dt

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import children, get as get_entry, gtime, gtime_of_iso, norm_dn, one, ou_entry, rdn_value
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import (TEMPLATE_CLASS, authority_entry, ca_templates_groups, cert_inventory_entry,
                                       common_name, endpoint_entry, issued_entry, serial_key, template_entry)
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, TEMPLATES, authority_dn
from opsdir_adapter_x509.certificates import certificate_facts
from opsdir_adapter_x509.reasons import reason_name
from .private_ca_access import ACM_PRINCIPAL, enrollment

ROOT = "private-ca/"
TYPES = {"ROOT": "root", "SUBORDINATE": "subordinate"}
STATES = {"CREATING": "pending", "PENDING_CERTIFICATE": "pending", "ACTIVE": "active", "DISABLED": "disabled",
          "EXPIRED": "expired", "DELETED": "deleted", "FAILED": "failed"}
SERVER, CLIENT, CODE, OCSP = "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3", "1.3.6.1.5.5.7.3.9"
# the extended key usages AWS fixes for each template family (AWS Private CA user guide, template definitions)
FAMILY_USAGES = {"EndEntityCertificate": (SERVER, CLIENT), "EndEntityClientAuthCertificate": (CLIENT,),
                 "EndEntityServerAuthCertificate": (SERVER,), "CodeSigningCertificate": (CODE,),
                 "OCSPSigningCertificate": (OCSP,)}
FRESH = dt.timedelta(days=1)          # an audit report older than this before the read leaves the inventory incomplete
PARTITION = "{partition}"


def _doc(get, name, kind=dict):
    return json_document(get(name) or "", kind)


def ca_id(arn):
    """A CA ARN's id (arn:<partition>:acm-pca:<region>:<account>:certificate-authority/<id>), or None."""
    tail = (arn or "").split(":certificate-authority/", 1)
    return tail[1].split("/", 1)[0] if len(tail) == 2 and tail[1] else None


def arn_part(arn, n):
    """The n-th colon-separated part of an ARN (3: region, 4: account), or None."""
    parts = (arn or "").split(":")
    return parts[n] if len(parts) > n and parts[n] else None


def template_name(arn):
    """An AWS template ARN's name (EndEntityCertificate/V1), or None."""
    tail = (arn or "").split(":template/", 1)
    return tail[1] if len(tail) == 2 and tail[1] else None


def template_usages(name):
    """The extended key usage OIDs AWS fixes for a template (by its family, the name before any _variant or /V1); ()
    for those that fix none."""
    return FAMILY_USAGES.get(name.split("/", 1)[0].split("_", 1)[0], ())


def endpoints(ca, region):
    """((kind, n, url, template or None), ...) of the URLs a CA writes into the certificates it issues: its CRL
    distribution point (a partitioned CRL's kept as a template) and its OCSP responder, when enabled."""
    rev = ca.get("RevocationConfiguration") or {}
    crl, ocsp = rev.get("CrlConfiguration") or {}, rev.get("OcspConfiguration") or {}
    found = []
    if crl.get("Enabled") and not (crl.get("CrlDistributionPointExtensionConfiguration") or {}).get("OmitExtension"):
        host = crl.get("CustomCname") or f"{crl.get('S3BucketName')}.s3.{region}.amazonaws.com"
        path = (crl.get("CustomPath") or "crl").strip("/")
        if crl.get("CrlType") == "PARTITIONED":
            url = f"http://{host}/{path}/{PARTITION}.crl"
            found.append(("crl", 1, url, url))
        else:
            found.append(("crl", 1, f"http://{host}/{path}/{ca_id(ca.get('Arn'))}.crl", None))
    if ocsp.get("Enabled"):
        found.append(("ocsp", 1, f"http://{ocsp.get('OcspCustomCname') or f'ocsp.acm-pca.{region}.amazonaws.com'}",
                      None))
    return tuple(found)


def ca_name(ca, facts):
    """A CA's name in the record: its certificate's subject CN, else its configured subject's, else its id."""
    configured = ((ca.get("CertificateAuthorityConfiguration") or {}).get("Subject") or {}).get("CommonName")
    cn = common_name(facts["subject"]) if facts else None
    return next((n for n in (cn, configured) if n and rdn_safe(n)), ca_id(ca.get("Arn")))


def report_time(listing):
    """(GeneralizedTime, datetime) of the newest audit report a listing names, or (None, None)."""
    times = sorted(t for t in (gtime_of_iso(r.get("LastModified")) for r in listing or () if isinstance(r, dict))
                   if t)
    if not times:
        return None, None
    return times[-1], dt.datetime.strptime(times[-1], "%Y%m%d%H%M%SZ").replace(tzinfo=dt.timezone.utc)


def issued_facts(row, ca):
    """The ciamIssuedCertificate facts of an audit report row (its serial as hex, its template as the CA's own), or
    None when it has no serial."""
    serial = serial_key(row.get("serial"))
    if not serial:
        return None
    revoked = row.get("revokedAt")
    name = template_name(row.get("templateArn"))
    return {"ciamSerialNumber": serial if len(serial) % 2 == 0 else f"0{serial}", "ciamFingerprint": None,
            "ciamSubject": row.get("subject") or row.get("Subject"),
            "ciamNotBefore": gtime_of_iso(row.get("notBefore")), "ciamNotAfter": gtime_of_iso(row.get("notAfter")),
            "ciamTemplateName": f"{ca}/{name}" if name else None,
            "ciamRequester": row.get("requestedByServicePrincipal"),
            "ciamRevokedAt": gtime_of_iso(revoked) if revoked else None,
            "ciamRevocationReason": reason_name(row.get("revocationReason")) if revoked else None}


def _create_command(arn, region):
    return (f"the CA's owner creates one: aws acm-pca create-certificate-authority-audit-report "
            f"--certificate-authority-arn {arn} --s3-bucket-name <the report bucket> --audit-report-response-format "
            f"JSON --region {region} (acm-pca:CreateCertificateAuthorityAuditReport; at most one per 30 minutes)")


def inventory_state(get, arn, region, at):
    """(state, problems, GeneralizedTime the inventory is of, report rows) of a CA's audit reports."""
    listing = _doc(get, "audit-reports.json", list)
    when, newest = report_time(listing)
    rows = _doc(get, "audit-report.json", list)
    if get("audit-reports.json") is None:
        return "incomplete", ("no audit report collected: name the report bucket (a collection source for "
                              "aws/private-ca, ciamSourceRef s3://<bucket>) and " + _create_command(arn, region),
                              ), gtime(at), ()
    if newest is None or rows is None:
        return "incomplete", (f"no audit report under audit-report/{ca_id(arn)}/ read: " +
                              _create_command(arn, region),), gtime(at), ()
    stale = at - newest > FRESH
    return ("incomplete" if stale else "complete",
            (f"the newest audit report is from {newest:%Y-%m-%d %H:%M}Z, {(at - newest).days} day(s) before the read: "
             "certificates issued since aren't in it; " + _create_command(arn, region),) if stale else (),
            when, tuple(r for r in rows if isinstance(r, dict)))


def _parent(ca, facts, by_subject, d):
    """The name of the CA that issued a subordinate's certificate: the CA in the export whose certificate's subject
    is its issuer, else the record's CA named after the issuer's common name; None when neither."""
    if ca.get("Type") != "SUBORDINATE" or not facts:
        return None
    found = by_subject.get(facts["issuer"])
    cn = common_name(facts["issuer"])
    return found or (cn if cn and rdn_safe(cn) and get_entry(d, authority_dn(cn)) is not None else None)


def read_ca(d, ca, get, iam, by_subject, at):
    """(Imported groups, notices) of one CA: its entry with what AWS says of it and its endpoints, its inventory
    from the newest audit report, and the templates that report shows as its own."""
    arn, region = ca.get("Arn"), arn_part(ca.get("Arn"), 3)
    facts = certificate_facts((_doc(get, "certificate.json") or {}).get("Certificate"))
    name = ca_name(ca, facts)
    if not name or not rdn_safe(name):
        return (), (f"{arn}: can't be named in the record: left out",)
    state, problems, when, rows = inventory_state(get, arn, region, at)
    issued = tuple((r, issued_facts(r, name)) for r in rows)
    unread = sum(1 for _, f in issued if f is None)
    problems = (*problems, *((f"{unread} audit report row(s) without a serial",) if unread else ()))
    used = tuple(dict.fromkeys(n for r in rows for n in (template_name(r.get("templateArn")),) if n))
    acm_used = {template_name(r.get("templateArn")) for r in rows if r.get("requestedByServicePrincipal") ==
                ACM_PRINCIPAL}
    policy, permissions = _doc(get, "policy.json"), _doc(get, "permissions.json")
    resource_policy = (policy or {}).get("Policy")
    made = tuple((t, enrollment(iam, resource_policy, permissions, arn, arn_part(arn, 4),
                                f"arn:{arn_part(arn, 1)}:acm-pca:::template/{t}", t in acm_used)) for t in used)
    templates = tuple(template_entry(d, f"{name}/{t}", t, None, None, template_usages(t),
                                     {"ciamSubjectFromRequest": True, "ciamApprovalRequired": False,
                                      "ciamRequiredSignatures": 0, "ciamEnrollee": enrollees,
                                      "ciamEnrollmentScope": scope}, authority=name)
                      for t, (enrollees, scope, _) in made)
    if not rows:     # no report read: the templates the record holds as the CA's are kept
        templates = tuple(t for t in children(d, TEMPLATES, TEMPLATE_CLASS)
                          if norm_dn(one(t, "ciamTemplateAuthority") or "") == norm_dn(authority_dn(name)))
    config = ca.get("CertificateAuthorityConfiguration") or {}
    found = endpoints(ca, region)
    status = STATES.get(ca.get("Status"), (ca.get("Status") or "").lower() or None)
    told = {"ciamCaType": TYPES.get(ca.get("Type")), "ciamCaState": status,
            "ciamCaKeyAlgorithm": config.get("KeyAlgorithm"), "ciamCaKeyStorage": ca.get("KeyStorageSecurityStandard"),
            "ciamCaKeyRef": None, "ciamParentAuthority": _parent(ca, facts, by_subject, d),
            "ciamCaRestorableUntil": gtime_of_iso(ca.get("RestorableUntil")) if status == "deleted" else None}
    authority = inventory_group(authority_entry(d, name, arn, tuple(rdn_value(t) for t in templates), told),
                                tuple(endpoint_entry(d, name, kind, n, url, t) for kind, n, url, t in found))
    inventory = inventory_group(cert_inventory_entry(d, name, when, state, problems, arn),
                                tuple(issued_entry(d, name, f["ciamSerialNumber"], f) for _, f in issued if f))
    notices = (*((f"{name}: no CA certificate read (state {ca.get('Status')}): named after its configured subject",)
                 if facts is None else ()),
               *((f"{name}: deleted, restorable until {ca.get('RestorableUntil')}",) if status == "deleted" else ()),
               *((f"{name}: its CRL is partitioned: each partition's file name is a GUID, kept as the template "
                  f"{PARTITION}",) if any(t for *_, t in found) else ()),
               *((f"{name}: in GovCloud (US) the CRL and OCSP hostnames follow AWS's general patterns, which nothing "
                  "documents separately: compare them with an issued certificate's CRL distribution point and "
                  "authority information access",) if (region or "").startswith("us-gov-") and found else ()),
               *(f"{name}/{t}: who may request from it is unknown ({why})" for t, (_, _, why) in made if why),
               f"{name} ({ca_id(arn)}): {sum(1 for _, f in issued if f)} certificate(s), {len(found)} endpoint(s), "
               f"{len(templates)} template(s), {state}" + (f" ({'; '.join(problems)})" if problems else ""))
    return (authority, inventory, *ca_templates_groups(d, name, templates)), notices


def _subjects(cas, get_of):
    """{a CA certificate's subject: the CA's name} of the CAs in the export."""
    found = ((ca, certificate_facts((_doc(get_of(ca), "certificate.json") or {}).get("Certificate"))) for ca in cas)
    return {f["subject"]: ca_name(ca, f) for ca, f in found if f}


def read_private_ca(files, d, patterns, at=None):
    """Imported: per CA the account owns, its entry with what AWS says of it and its endpoints, its inventory from
    the newest audit report and the templates that report shows, each replacing the record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the CAs were read)",))
    get = files.get
    cas = tuple(c for c in (json_document(get(f"{ROOT}cas.json") or "", dict) or {}).get("CertificateAuthorities")
                or () if isinstance(c, dict) and ca_id(c.get("Arn")))
    shared = tuple(c.get("Arn") for c in (json_document(get(f"{ROOT}shared-cas.json") or "", dict) or {})
                   .get("CertificateAuthorities") or () if isinstance(c, dict))
    iam = json_document(get(f"{ROOT}iam.json") or "", dict)
    get_of = lambda ca: (lambda name: get(f"{ROOT}{ca_id(ca.get('Arn'))}/{name}"))      # noqa: E731
    by_subject = _subjects(cas, get_of)
    when = at if at.tzinfo else at.replace(tzinfo=dt.timezone.utc)
    read = tuple(read_ca(d, ca, get_of(ca), iam, by_subject, when) for ca in cas)
    return Imported(containers=(ou_entry(AUTHORITIES), ou_entry(ISSUED), ou_entry(TEMPLATES)),
                    groups=tuple(g for groups, _ in read for g in groups),
                    notices=(*(n for _, notices in read for n in notices),
                             *((f"{len(shared)} CA(s) shared from other accounts not read (their owner holds their "
                                f"audit reports): {', '.join(shared[:5])}",) if shared else ()),
                             *(("the account's IAM policies weren't read (private-ca/iam.json): who may request "
                                "certificates is unknown",) if cas and iam is None else ()),
                             *(("no CAs (private-ca/cas.json, as `opsdir collect` saves it)",) if not cas else ())))


PRIVATE_CA_IMPORTER = Importer("private-ca", "AWS Private CA: each CA's state, key and hierarchy, revocation "
                                             "endpoints, templates used and the certificates its newest audit report "
                                             "lists, metadata only (as `opsdir collect` saves them)",
                               read_private_ca, reference=True)
