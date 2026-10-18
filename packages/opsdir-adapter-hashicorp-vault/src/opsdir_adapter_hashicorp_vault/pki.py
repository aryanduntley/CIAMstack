"""Vault PKI inventory (the importer `hashicorp-vault/pki`): each PKI mount's CA, its revocation endpoints, its roles as
CA-scoped templates and the certificates it keeps, read into the core pki domain's records (domains.pki.issued),
metadata only. Pure.

The export holds, per mount, Vault's answers as `opsdir collect` saves them (pki_collect.py) or
scripts/export-vault-pki.sh writes them, each `vault read -format=json` / HTTP API JSON (a listing may be the CLI's
bare array):
  pki/<mount>/issuers.json, issuers/<issuer id>.json     the mount's issuers (each its certificate and AIA overrides)
  pki/<mount>/config/{urls,issuers,cluster,crl,auto-tidy}.json
  pki/<mount>/roles.json, roles/<role>.json
  pki/<mount>/certs.json, certs/<serial, - for :>.json   the serials the mount keeps, each certificate (public PEM,
                                                         revocation time and reason)
  pki/<mount>/policies.json, policies/<name>.json        optional: the ACL policies (sys/policies/acl)
A mount is one CA: named after its default issuer's subject common name (its certificate's CN, as an AD CS CA's is),
else after the mount; ciamProviderRef is the mount. Its revocation endpoints are what its default issuer writes into
the certificates it issues: the issuer's own AIA URLs when it has any, else the mount's (config/urls), with Vault's
URL template variables ({{issuer_id}}, {{cluster_path}}, {{cluster_aia_path}}) filled from the export when templating
is on; one left unfilled keeps the template (description) and is named. Each role is a template of that CA only
(ciamTemplateAuthority; cn <CA>/<role>, roles.py, policies.py); the CA's roles replace those the record holds as its.

A certificate (cn: its serial as Vault lists it, colons) is read from its public PEM (opsdir-adapter-x509's
certificate_facts): serial, SHA-256, subject, validity. Vault records neither the role it was issued from nor who asked
for it, nor a revocation reason: a revoked one is `unspecified` at its revocation time. The inventory is complete for
the certificates Vault keeps: incomplete when a listed certificate wasn't read or read as no certificate, when the
listing is missing (Vault answers an empty one with 404) or when a role keeps none of what it issues (no_store) or
wasn't read; denied when the listing was refused. Auto-tidy removing expired certificates from the store, and CRL or
OCSP building disabled, are named.
"""
from functools import reduce

from opsdir.core.contract import Imported, Importer
from opsdir.core.directory import get as get_entry, gtime, gtime_of_iso, ou_entry, rdn_value
from opsdir.core.naming import rdn_safe
from opsdir.core.sources import json_document
from opsdir.domains.pki.inventory import inventory_group
from opsdir.domains.pki.issued import (authority_entry, ca_templates_groups, cert_inventory_entry, common_name,
                                       endpoint_entry, issued_entry, revocation_reason, template_entry)
from opsdir.domains.pki.naming import AUTHORITIES, ISSUED, TEMPLATES, template_dn
from opsdir_adapter_x509.certificates import certificate_facts
from .policies import enrollment, granting, policy_rules, role_paths, verbatim_paths
from .roles import max_validity_days, role_usages, subject_from_request

ROOT, ANCHOR = "pki/", "/issuers.json"
# (Vault's AIA field, the record's revocation endpoint kind), in the order endpoints are numbered
URL_KINDS = (("crl_distribution_points", "crl"), ("delta_crl_distribution_points", "delta-crl"),
             ("ocsp_servers", "ocsp"), ("issuing_certificates", "ca-issuers"))
TEMPLATE_VARIABLES = ("{{issuer_id}}", "{{cluster_path}}", "{{cluster_aia_path}}")


def answer_data(text):
    """The data of a Vault answer (its JSON envelope's data, or a bare object), or None."""
    doc = json_document(text or "", dict)
    return (doc.get("data") if isinstance(doc.get("data"), dict) else None if "data" in doc else doc) \
        if doc is not None else None


def listing(text):
    """The keys of a Vault listing (the CLI's bare array, or an answer's data.keys), or None when it isn't one."""
    doc = json_document(text or "")
    keys = doc if isinstance(doc, list) else (answer_data(text) or {}).get("keys") if isinstance(doc, dict) else None
    return tuple(k for k in keys if isinstance(k, str)) if isinstance(keys, list) else None


def file_name(key):
    """A listed key as the file holding its answer is named (a serial's colons as dashes)."""
    return key.replace(":", "-")


def mounts(files):
    """The mounts an export holds (each with its issuers listing), in order; a mount's config/issuers.json isn't one."""
    found = {p[len(ROOT):-len(ANCHOR)] for p in files if p.startswith(ROOT) and p.endswith(ANCHOR)}
    return tuple(sorted(m for m in found if not (m.endswith("/config") and m[:-len("/config")] in found)))


def aia_endpoints(issuer, urls, cluster, issuer_id):
    """((kind, n, url, template or None), ...) of the URLs an issuer writes into what it issues: its own AIA fields
    when it sets any, else the mount's; template variables filled when templating is on (template None), else kept
    with the template given."""
    own = issuer is not None and any(issuer.get(f) for f, _ in URL_KINDS)
    source = issuer if own else urls or {}
    templating = source.get("enable_aia_url_templating" if own else "enable_templating")
    values = {"{{issuer_id}}": issuer_id, "{{cluster_path}}": (cluster or {}).get("path"),
              "{{cluster_aia_path}}": (cluster or {}).get("aia_path")}
    def filled(url):
        out = reduce(lambda u, var: u.replace(var, values[var]) if templating and values[var] else u,
                     TEMPLATE_VARIABLES, url)
        return out, (url if "{{" in out else None)
    return tuple((kind, n, *filled(str(url))) for field, kind in URL_KINDS
                 for n, url in enumerate(source.get(field) or (), 1))


def issued_facts(cert):
    """(the issued certificate facts of a certificate answer, or None when it holds no certificate): from its
    public PEM, and its revocation (Vault records no reason: unspecified)."""
    facts = certificate_facts((cert or {}).get("certificate"))
    if facts is None:
        return None
    revoked = bool(cert.get("revocation_time")) or bool(cert.get("revocation_time_rfc3339"))
    reason = cert.get("revocation_reason")
    return {"ciamSerialNumber": facts["serial"], "ciamFingerprint": facts["sha256"], "ciamSubject": facts["subject"],
            "ciamNotBefore": facts["not_before"], "ciamNotAfter": facts["not_after"], "ciamTemplateName": None,
            "ciamRequester": None, "ciamRevokedAt": gtime_of_iso(cert.get("revocation_time_rfc3339")) if revoked
            else None, "ciamRevocationReason": revocation_reason(reason if isinstance(reason, int) else 0) if revoked
            else None}


def _policies(get):
    names = listing(get("policies.json"))
    return None if names is None else {n: policy_rules((answer_data(get(f"policies/{n}.json")) or {}).get("policy"))
                                       if get(f"policies/{n}.json") is not None else None for n in names}


def _role(d, ca, mount, name, role, policies, issuer_refs):
    """(template entry or None, notices) of one role."""
    if role is None:
        return None, (f"{ca}: role {name} wasn't read",)
    days, why = max_validity_days(role)
    usages, unknown = role_usages(role)
    enrollees, scope, unknown_why = enrollment(policies, role_paths(mount, name, issuer_refs))
    rights = {"ciamSubjectFromRequest": subject_from_request(role), "ciamApprovalRequired": False,
              "ciamRequiredSignatures": 0, "ciamEnrollee": enrollees, "ciamEnrollmentScope": scope}
    return (template_entry(d, f"{ca}/{name}", None, None, days, usages, rights, authority=ca),
            (*((f"{ca}/{name}: {why}",) if why else ()),
             *((f"{ca}/{name}: ext_key_usage {', '.join(unknown)} unknown: left out",) if unknown else ()),
             *((f"{ca}/{name}: who may request from it is unknown ({unknown_why})",) if unknown_why else ())))


def _certificates(d, ca, get):
    """(issued entries, problems, refused) of a mount's certificate listing."""
    text = get("certs.json")
    serials = listing(text)
    if serials is None:
        refused = text is not None and "permission denied" in text
        return (), (("the certificate listing was refused: permission denied",) if refused else
                    ("no certificate listing (certs.json; Vault answers an empty listing with 404)",) if text is None
                    else ("the certificate listing (certs.json) isn't a listing",)), refused
    read = tuple((s, issued_facts(answer_data(get(f"certs/{file_name(s)}.json")))) for s in serials)
    unread = tuple(s for s, f in read if f is None)
    unnamed = tuple(s for s, f in read if f is not None and not rdn_safe(s))
    return (tuple(issued_entry(d, ca, s, f) for s, f in read if f is not None and s not in unnamed),
            (*((f"{len(unread)} listed certificate(s) not read or not a certificate: {', '.join(unread[:5])}",)
               if unread else ()),
             *((f"{len(unnamed)} serial(s) can't be named in the record",) if unnamed else ())), False)


def _settings_notices(ca, crl, tidy):
    return (*((f"{ca}: CRL building is disabled (config/crl disable)",) if crl.get("disable") else ()),
            *((f"{ca}: its OCSP responder is disabled (config/crl ocsp_disable)",) if crl.get("ocsp_disable") else ()),
            *((f"{ca}: auto-tidy removes certificates expired more than {tidy.get('safety_buffer')}s ago from the "
               "store: they leave the inventory",) if tidy.get("enabled") and tidy.get("tidy_cert_store") else ()))


def read_mount(d, mount, get, when):
    """(Imported groups, notices) of one mount: its CA with its endpoints, its inventory and its roles."""
    ids = listing(get("issuers.json")) or ()
    issuers = {i: answer_data(get(f"issuers/{i}.json")) for i in ids}
    default_id = (answer_data(get("config/issuers.json")) or {}).get("default")
    default_id = default_id if issuers.get(default_id) else next((i for i, v in issuers.items() if v and
                                                                  v.get("key_id")), None)
    default = issuers.get(default_id)
    facts = certificate_facts((default or {}).get("certificate"))
    cn = common_name(facts["subject"]) if facts else None
    ca = cn if cn and rdn_safe(cn) else mount
    if not rdn_safe(ca):
        return (), (f"{mount}: can't be named in the record: left out",)
    found = aia_endpoints(default, answer_data(get("config/urls.json")), answer_data(get("config/cluster.json")),
                          default_id)
    refs = (*ids, *((v or {}).get("issuer_name") for v in issuers.values()), "default")
    policies = _policies(get)
    names = listing(get("roles.json")) or ()
    roles = {n: answer_data(get(f"roles/{n}.json")) for n in names}
    made = tuple((n, *_role(d, ca, mount, n, r, policies, refs)) for n, r in roles.items())
    # a role that wasn't read keeps the template the record holds for it
    templates = tuple(t if t is not None else get_entry(d, template_dn(f"{ca}/{n}")) for n, t, _ in made)
    templates = tuple(t for t in templates if t is not None)
    issued, problems, refused = _certificates(d, ca, get)
    problems = (*problems,
                *(f"role {n} keeps none of the certificates it issues (no_store): they can't be listed"
                  for n, r in roles.items() if r and r.get("no_store")),
                *(f"role {n} wasn't read: whether it keeps what it issues is unknown" for n, r in roles.items()
                  if r is None))
    state = "denied" if refused else "incomplete" if problems else "complete"
    verbatim = granting(policies or {}, verbatim_paths(mount, refs))
    notices = (*((f"{mount}: no default issuer's certificate read: the CA is named after the mount",)
                 if facts is None else ()),
               *(f"{ca}: endpoint {kind}-{n} keeps Vault's template {t!r} (variables not filled)"
                 for kind, n, _, t in found if t),
               *(n for _, _, ns in made for n in ns),
               *((f"{ca}: policies {', '.join(verbatim)} may sign any request whatever the roles allow "
                  "(sign-verbatim)",) if verbatim else ()),
               *_settings_notices(ca, answer_data(get("config/crl.json")) or {},
                                  answer_data(get("config/auto-tidy.json")) or {}),
               f"{ca} ({mount}): {len(issued)} certificate(s), {len(found)} endpoint(s), {len(templates)} role(s), "
               f"{state}" + (f" ({'; '.join(problems)})" if problems else ""))
    listed = tuple(rdn_value(t) for t in templates)
    authority = inventory_group(authority_entry(d, ca, mount, listed),
                                tuple(endpoint_entry(d, ca, kind, n, url, t) for kind, n, url, t in found))
    inventory = inventory_group(cert_inventory_entry(d, ca, when, state, problems, mount), issued)
    return (authority, inventory, *ca_templates_groups(d, ca, templates)), notices


def read_pki(files, d, patterns, at=None):
    """Imported: per mount in the export, its CA with its revocation endpoints, its issued-certificate inventory and
    its roles as the CA's own templates, each replacing the record's."""
    if at is None:
        return Imported((), (), ("an inventory is dated: give --at (when the mount was read)",))
    read = tuple(read_mount(d, m, lambda name, m=m: files.get(f"{ROOT}{m}/{name}"), gtime(at)) for m in mounts(files))
    return Imported(containers=(ou_entry(AUTHORITIES), ou_entry(ISSUED), ou_entry(TEMPLATES)),
                    groups=tuple(g for groups, _ in read for g in groups),
                    notices=(*(n for _, notices in read for n in notices),
                             *(("no PKI mounts (pki/<mount>/issuers.json, as `opsdir collect` saves them)",)
                               if not read else ())))


PKI_IMPORTER = Importer("pki", "Vault PKI mounts' CA, revocation endpoints, roles and the certificates they keep, "
                               "metadata only (Vault's answers as `opsdir collect` or scripts/export-vault-pki.sh "
                               "save them)", read_pki, reference=True)
