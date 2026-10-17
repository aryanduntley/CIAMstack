"""Google Cloud Certificate Authority Service inventory (the importer `gcp/private-ca`): each CA of the project's CA
pools, its revocation endpoints, its pool's issuance policy and the location's certificate templates as its own
templates, and the certificates its pool keeps, read into the core pki domain's records (domains.pki.issued),
metadata only. Pure.

The export holds gcloud's answers as `opsdir collect` saves them (collect.py, private_ca_steps), each --format=json:
  private-ca/pools.json                              privateca pools list (every location)
  private-ca/project-iam.json                        projects get-iam-policy (roles granted on the project)
  private-ca/<location>/<pool>/roots.json            privateca roots list --pool --location
  private-ca/<location>/<pool>/subordinates.json     privateca subordinates list --pool --location
  private-ca/<location>/<pool>/iam.json              privateca pools get-iam-policy
  private-ca/<location>/<pool>/certificates.json     privateca certificates list --issuer-pool (Enterprise tier only;
                                                     trimmed to what is read here)
  private-ca/<location>/templates.json               privateca templates list --location
  private-ca/<location>/templates/<template>/iam.json  privateca templates get-iam-policy
A CA is named after its certificate's subject common name (else its id); ciamProviderRef is its resource name. What
Google says of it: root (SELF_SIGNED) or subordinate, its state (STAGED and AWAITING_USER_ACTIVATION are pending),
its key: a Google-managed HSM key's algorithm, or the Cloud KMS key version it signs with (a reference), and for a
subordinate its parent (subordinateConfig's CA, else the CA whose certificate's subject is its issuer). Its endpoints
are what it writes into what it issues: its CRL and CA certificate URLs (its own when it sets them, else the ones it
publishes) and the OCSP servers its pool's baseline puts in certificates (CAS runs no OCSP responder).

Templates are the CA's own (ciamTemplateAuthority): <CA>/<pool> for requests without a certificate template (the
pool's issuance policy) and <CA>/<pool>/<template> for each template of the pool's location (the pool's policy and the
template's together): the requester names the subject unless both forbid subject and alternative-name passthrough;
the extended key usages are the baseline's and the template's (none when the request may pass its own through, or
when neither sets any: any purpose); the longest validity is the smaller maximum lifetime; no approval, no
signature; who may request from private_ca_access. The inventory is a pool's certificates by issuing CA: complete for
an Enterprise pool whose listing was read, incomplete for a DevOps pool (it keeps no certificates: only Cloud Audit
Logs record what it issues) or a listing not read. A certificate (cn: its serial) is read from its public PEM
(certificate_facts: serial, SHA-256, subject, validity), its template as the CA's own, its revocation by RFC name
(Google's enum names, never its numbers); Google records no requester.
"""
import math

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get as get_entry, gtime, gtime_of_iso, ou_entry
from opsdir.core.inventory import duration_seconds
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import (authority_entry, ca_templates_groups, cert_inventory_entry, common_name,
                                       endpoint_entry, issued_entry, template_entry)
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, TEMPLATES, authority_dn
from opsdir_adapter_x509.certificates import certificate_facts
from opsdir_adapter_x509.reasons import reason_name
from .private_ca_access import enrollment

ROOT = "private-ca/"
DAY = 86400
TYPES = {"SELF_SIGNED": "root", "SUBORDINATE": "subordinate"}
STATES = {"ENABLED": "active", "DISABLED": "disabled", "STAGED": "pending", "AWAITING_USER_ACTIVATION": "pending",
          "DELETED": "deleted"}
# X509Parameters.keyUsage.extendedKeyUsage flags
EKU_FLAGS = (("serverAuth", "1.3.6.1.5.5.7.3.1"), ("clientAuth", "1.3.6.1.5.5.7.3.2"),
             ("codeSigning", "1.3.6.1.5.5.7.3.3"), ("emailProtection", "1.3.6.1.5.5.7.3.4"),
             ("timeStamping", "1.3.6.1.5.5.7.3.8"), ("ocspSigning", "1.3.6.1.5.5.7.3.9"))


def resource_part(name, collection):
    """The id after <collection>/ in a resource name (projects/p/locations/l/caPools/x: caPools -> x), or None."""
    parts = (name or "").split("/")
    return parts[parts.index(collection) + 1] if collection in parts[:-1] else None


def _list(get, name):
    found = json_document(get(name) or "", list)
    return tuple(x for x in found or () if isinstance(x, dict)) if found is not None else None


def x509_usages(params):
    """The extended key usage OIDs X509Parameters set (its flags and unknownExtendedKeyUsages)."""
    eku = ((params or {}).get("keyUsage") or {})
    flags = eku.get("extendedKeyUsage") or {}
    return (*(oid for flag, oid in EKU_FLAGS if flags.get(flag)),
            *(".".join(str(n) for n in (o or {}).get("objectIdPath") or ()) for o in eku.get("unknownExtendedKeyUsages")
              or ()))


def passes_usages(*constraints):
    """Whether a request may pass its own extended key usages through (passthroughExtensions naming them)."""
    return any("EXTENDED_KEY_USAGE" in ((c or {}).get("knownExtensions") or ()) for c in constraints)


def names_subject(*constraints):
    """Whether the requester names the subject: unless every identity constraint given forbids both subject and
    alternative-name passthrough (none given: nothing forbids it)."""
    given = tuple(c for c in constraints if c is not None)
    return not given or all(c.get("allowSubjectPassthrough") or c.get("allowSubjectAltNamesPassthrough") for c in given)


def lifetime_days(*lifetimes):
    """The smallest of maximum lifetimes ('2592000s') in whole days rounded up, or None when none is set."""
    found = tuple(s for s in (duration_seconds(str(x)) for x in lifetimes if x) if s)
    return math.ceil(min(found) / DAY) if found else None


def template_facts(pool, template=None):
    """(subject from request, extended key usages, longest validity in days) of a pool's issuance policy, with a
    template's when given."""
    policy = pool.get("issuancePolicy") or {}
    t = template or {}
    usages = () if passes_usages(policy.get("passthroughExtensions"), t.get("passthroughExtensions")) else \
        tuple(dict.fromkeys((*x509_usages(policy.get("baselineValues")), *x509_usages(t.get("predefinedValues")))))
    return (names_subject(policy.get("identityConstraints"), *((t.get("identityConstraints"),) if template else ())),
            usages, lifetime_days(policy.get("maximumLifetime"), t.get("maximumLifetime")))


def ca_endpoints(ca, pool):
    """((kind, n, url, None), ...) of what a CA writes into what it issues: its CRL and CA certificate URLs (its own
    when it sets them, else those it publishes) and its pool's baseline OCSP servers."""
    own, published = ca.get("userDefinedAccessUrls") or {}, ca.get("accessUrls") or {}
    crls = own.get("crlAccessUrls") or published.get("crlAccessUrls") or ()
    issuers = own.get("aiaIssuingCertificateUrls") or (
        (published["caCertificateAccessUrl"],) if published.get("caCertificateAccessUrl") else ())
    ocsp = ((pool.get("issuancePolicy") or {}).get("baselineValues") or {}).get("aiaOcspServers") or ()
    return tuple((kind, n, str(url), None) for kind, urls in (("crl", crls), ("ocsp", ocsp), ("ca-issuers", issuers))
                 for n, url in enumerate(urls, 1))


def ca_facts(ca, names, by_subject, facts, d):
    """What Google says of a CA (AUTHORITY_FACTS): type, state, key algorithm, storage, key reference and parent."""
    spec = ca.get("keySpec") or {}
    parent_ref = (ca.get("subordinateConfig") or {}).get("certificateAuthority")
    issuer_cn = common_name(facts["issuer"]) if facts else None
    parent = (names.get(parent_ref) if parent_ref else None) or (by_subject.get(facts["issuer"]) if facts and
                                                                  ca.get("type") == "SUBORDINATE" else None)
    if parent is None and ca.get("type") == "SUBORDINATE" and issuer_cn and rdn_safe(issuer_cn) \
            and get_entry(d, authority_dn(issuer_cn)) is not None:
        parent = issuer_cn
    return {"ciamCaType": TYPES.get(ca.get("type")), "ciamCaState": STATES.get(ca.get("state")),
            "ciamCaKeyAlgorithm": spec.get("algorithm"),
            "ciamCaKeyStorage": "Google-managed HSM" if spec.get("algorithm") else
            "Cloud KMS key" if spec.get("cloudKmsKeyVersion") else None,
            "ciamCaKeyRef": spec.get("cloudKmsKeyVersion"), "ciamParentAuthority": parent}


def ca_name(ca, facts):
    """A CA's record name: its certificate's subject CN, else its id."""
    cn = common_name(facts["subject"]) if facts else None
    return cn if cn and rdn_safe(cn) else resource_part(ca.get("name"), "certificateAuthorities")


def issued_facts(cert, ca, pool):
    """The ciamIssuedCertificate facts of a certificate (from its public PEM; its template as the CA's own; its
    revocation), or None when it holds no certificate."""
    facts = certificate_facts(cert.get("pemCertificate"))
    if facts is None:
        return None
    rev = cert.get("revocationDetails")
    template = resource_part(cert.get("certificateTemplate"), "certificateTemplates")
    return {"ciamSerialNumber": facts["serial"], "ciamFingerprint": facts["sha256"], "ciamSubject": facts["subject"],
            "ciamNotBefore": facts["not_before"], "ciamNotAfter": facts["not_after"],
            "ciamTemplateName": f"{ca}/{pool}/{template}" if template else f"{ca}/{pool}", "ciamRequester": None,
            "ciamRevokedAt": gtime_of_iso((rev or {}).get("revocationTime")) if rev is not None else None,
            "ciamRevocationReason": reason_name((rev or {}).get("revocationState")) if rev is not None else None}


def _templates(d, ca, pool_id, pool, templates, project_policy, pool_policy, template_policy):
    """(template entries, notices) of a CA's own templates: the pool's policy alone, then with each template."""
    def entry(name, template, policy):
        subject, usages, days = template_facts(pool, template)
        enrollees, scope, why = enrollment(pool_policy, policy, project_policy, template is not None)
        rights = {"ciamSubjectFromRequest": subject, "ciamApprovalRequired": False, "ciamRequiredSignatures": 0,
                  "ciamEnrollee": enrollees, "ciamEnrollmentScope": scope}
        return (template_entry(d, name, (template or {}).get("description"), None, days, usages, rights,
                               authority=ca),
                f"{name}: who may request from it is unknown ({why})" if why else None)
    made = (entry(f"{ca}/{pool_id}", None, None),
            *(entry(f"{ca}/{pool_id}/{t_id}", t, template_policy(t_id)) for t in templates
              for t_id in (resource_part(t.get("name"), "certificateTemplates"),) if t_id and rdn_safe(t_id)))
    return tuple(e for e, _ in made), tuple(n for _, n in made if n)


def read_ca(d, ca, pool, certs, templates, policies, names, by_subject, at):
    """(Imported groups, notices) of one CA of a pool: its entry with Google's facts and its endpoints, its inventory
    (the pool's certificates it issued; certs None: no listing read) and its own templates. policies: (the project's
    IAM policy, the pool's, template id -> the template's)."""
    pool_id, location = resource_part(pool.get("name"), "caPools"), resource_part(pool.get("name"), "locations")
    facts = certificate_facts(next(iter(ca.get("pemCaCertificates") or ()), None))
    name = ca_name(ca, facts)
    if not name or not rdn_safe(name):
        return (), (f"{ca.get('name')}: can't be named in the record: left out",)
    made, said = _templates(d, name, pool_id, pool, templates, *policies)
    own = tuple(c for c in certs or () if c.get("issuerCertificateAuthority") == ca.get("name"))
    issued = tuple(f for f in (issued_facts(c, name, pool_id) for c in own) if f)
    devops = pool.get("tier") == "DEVOPS"
    problems = (*(("a DevOps tier pool keeps no certificates: only Cloud Audit Logs record what it issues",)
                  if devops else ()),
                *((f"no certificate listing of pool {pool_id} read",) if certs is None and not devops else ()),
                *((f"{len(own) - len(issued)} listed certificate(s) without a certificate",)
                  if len(own) > len(issued) else ()))
    state = "incomplete" if problems else "complete"
    found = ca_endpoints(ca, pool)
    authority = inventory_group(authority_entry(d, name, ca.get("name"), tuple(e.attrs["cn"][0] for e in made),
                                                ca_facts(ca, names, by_subject, facts, d)),
                                tuple(endpoint_entry(d, name, kind, n, url, t) for kind, n, url, t in found))
    inventory = inventory_group(cert_inventory_entry(d, name, at, state, problems, ca.get("name")),
                                tuple(issued_entry(d, name, f["ciamSerialNumber"], f) for f in issued))
    return ((authority, inventory, *ca_templates_groups(d, name, made)),
            (*said, f"{name} ({location}/{pool_id}, {pool.get('tier')}): {len(issued)} certificate(s), "
                    f"{len(found)} endpoint(s), {len(made)} template(s), {state}"
             + (f" ({'; '.join(problems)})" if problems else "")))


def read_pool(d, pool, get, location_get, project_policy, names, by_subject, at):
    """(Imported groups, notices) of one CA pool: each of its CAs (read_ca)."""
    cas = (*(_list(get, "roots.json") or ()), *(_list(get, "subordinates.json") or ()))
    policies = (project_policy, json_document(get("iam.json") or "", dict),
                lambda t: json_document(location_get(f"templates/{t}/iam.json") or "", dict))
    read = tuple(read_ca(d, ca, pool, _list(get, "certificates.json"), _list(location_get, "templates.json") or (),
                         policies, names, by_subject, at) for ca in cas)
    return tuple(g for groups, _ in read for g in groups), tuple(n for _, notices in read for n in notices)


def _pool_get(get, pool):
    folder = f"{ROOT}{resource_part(pool.get('name'), 'locations')}/{resource_part(pool.get('name'), 'caPools')}/"
    return lambda name: get(f"{folder}{name}")


def _naming(pools, get):
    """({CA resource name: record name}, {CA certificate subject: record name}) of every CA in the export."""
    found = tuple((ca, certificate_facts(next(iter(ca.get("pemCaCertificates") or ()), None)))
                  for p in pools for f in ("roots.json", "subordinates.json")
                  for ca in _list(_pool_get(get, p), f) or ())
    return ({ca.get("name"): ca_name(ca, facts) for ca, facts in found},
            {facts["subject"]: ca_name(ca, facts) for ca, facts in found if facts})


def read_private_ca(files, d, patterns, at=None):
    """Imported: per CA of the project's pools, its entry with Google's facts and endpoints, its inventory and its
    own templates, each replacing the record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the pools were read)",))
    get = files.get
    pools = _list(get, f"{ROOT}pools.json") or ()
    project_policy = json_document(get(f"{ROOT}project-iam.json") or "", dict)
    names, by_subject = _naming(pools, get)
    read = tuple(read_pool(d, p, _pool_get(get, p),
                           lambda name, p=p: get(f"{ROOT}{resource_part(p.get('name'), 'locations')}/{name}"),
                           project_policy, names, by_subject, gtime(at)) for p in pools if resource_part(
                               p.get("name"), "caPools"))
    return Imported(containers=(ou_entry(AUTHORITIES), ou_entry(ISSUED), ou_entry(TEMPLATES)),
                    groups=tuple(g for groups, _ in read for g in groups),
                    notices=(*(n for _, notices in read for n in notices),
                             *(("roles granted on the folders and organization above the project aren't read: they "
                                "may let more members request certificates",) if pools else ()),
                             *(("no CA pools (private-ca/pools.json, as `opsdir collect` saves it)",)
                               if not pools else ())))


PRIVATE_CA_IMPORTER = Importer("private-ca", "Google Cloud Certificate Authority Service: each CA's state, key and "
                                             "hierarchy, revocation endpoints, its pool's policy and templates, and "
                                             "the certificates the pool keeps, metadata only (as `opsdir collect` "
                                             "saves them)", read_private_ca)
