"""Key reports, pure functions of a snapshot: where an environment keeps every key and secret (placement), how
spread out each credential is (sprawl), and everything a rotation touches (rotation impact)."""
from ...core.directory import follow, follow_all, get, is_a, one, rdn_value, referrers, values
from ...core.environment import env_model, environment_of
from ...core.findings import owner_label, responsible
from ...core.naming import env_label
from .checks import CERTIFICATE_USE
from .credentials import (all_material_bindings, binding_for, bindings_everywhere, certificates_keyed_by,
                          credential_for_role, credentials, distinct_bindings, linked_settings,
                          material_bindings, rotate_by)

KEYS_HEADERS = ("credential", "type", "role", "store", "reference", "protection", "auto-rotate", "rotate by",
                "replicas", "users", "status")
SPRAWL_HEADERS = ("credential", "role", "type", "continuity", "environments", "stores", "copies", "certificates",
                  "linked settings", "used in", "problem")
IMPACT_HEADERS = ("step", "what", "where", "owner")


def scheme(uri):
    return uri.split("://", 1)[0] if uri else ""


def _joined(xs):
    return ", ".join(xs)


def _yes_no(v):
    return {"TRUE": "yes", "FALSE": "no"}.get(v, "")


# ------------------------------------------------------------------ placement
def binding_status(d, credential, b):
    """What to know about how an environment holds a credential: HSM required but protected in software, and where
    its material was carried over from; else 'ok'. (Whether carry-over material still has to be copied depends on
    the move, so the planner says so, not this report.)"""
    source = follow(d, b, "ciamMaterialFrom")
    in_software = one(b, "ciamProtectionLevel", "software") == "software"
    notes = (*(("HSM required, the store protects it in software",)
               if one(credential, "ciamHsmRequired") == "TRUE" and in_software else ()),
             *((f"carried over from {env_label(environment_of(source))}",) if source else ()))
    return "; ".join(notes) or "ok"


def _due(credential, b, as_of):
    """'rotation overdue' when the material was due for rotation before as_of."""
    due = rotate_by(credential, b)
    return f"rotation overdue (due {due})" if due and as_of and due < as_of else None


def _placement_row(m, credential, as_of=None):
    b = binding_for(m, credential)
    name, kind, role = one(credential, "cn"), one(credential, "ciamCredentialType"), one(credential, "ciamBindingRole")
    if b is None:
        return (name, kind, role, "", "", "", "", "", "", "", "UNBOUND")
    uri = one(b, "ciamRefUri")
    return (name, kind, role, scheme(uri), uri, one(b, "ciamProtectionLevel", ""), _yes_no(one(b, "ciamAutoRotate")),
            str(rotate_by(credential, b) or ""), _joined(values(b, "ciamReplicaRegion")),
            _joined(values(b, "ciamKeyUser")),
            "; ".join(s for s in (_due(credential, b, as_of), binding_status(m.d, credential, b)) if s and s != "ok")
            or "ok")


def _undocumented_row(b):
    uri = one(b, "ciamRefUri")
    return ("-", "", one(b, "ciamBindingRole"), scheme(uri), uri, one(b, "ciamProtectionLevel", ""),
            _yes_no(one(b, "ciamAutoRotate")), "", _joined(values(b, "ciamReplicaRegion")),
            _joined(values(b, "ciamKeyUser")), "undocumented: no credential describes this role")


def key_placement_rows(d, dn, as_of=None):
    """Where the environment (spec or DN) keeps every credential (rotations overdue as of as_of marked), credentials it
    doesn't bind, and material bindings no credential describes."""
    m = env_model(d, dn)
    creds = credentials(d)
    described = {one(c, "ciamBindingRole") for c in creds}
    return [*(_placement_row(m, c, as_of) for c in creds),
            *(_undocumented_row(b) for b in material_bindings(m) if one(b, "ciamBindingRole") not in described)]


# ------------------------------------------------------------------ sprawl
def _sprawl_row(d, role, credential=None):
    held = bindings_everywhere(d, role)
    distinct = tuple(b for b, _ in distinct_bindings(held))
    copies = tuple(uri for b in distinct for uri in values(b, "ciamCopyRef"))
    stores = dict.fromkeys(scheme(u) for u in (*(one(b, "ciamRefUri") for b in distinct), *copies))
    problem = ("bound in no environment" if credential is not None and not held
               else "" if credential is not None else "no credential describes this role")
    return (one(credential, "cn") if credential else "-", role,
            one(credential, "ciamCredentialType", "") if credential else "",
            one(credential, "ciamContinuity", "") if credential else "",
            _joined(env_label(env) for env, _ in held), _joined(stores), len(copies),
            _joined(one(c, "cn") for c in certificates_keyed_by(d, role)), len(linked_settings(d, role)),
            _joined(rdn_value(e) for e in follow_all(d, credential, "ciamUsedIn") if e) if credential else "",
            problem)


def sprawl_rows(d, dn=None):
    """Every credential: which environments and stores hold it, its other copies, the certificates keyed by it, the
    config settings linked to it and where it is used; then roles holding key material (bound somewhere, or a
    certificate's key role) that no credential describes."""
    creds = credentials(d)
    described = {one(c, "ciamBindingRole") for c in creds}
    orphans = dict.fromkeys((*(one(b, "ciamBindingRole") for _, b in all_material_bindings(d)),
                             *(one(c, "ciamKeyRole") for c in d.entries.values()
                               if is_a(c, "ciamCertificate") and one(c, "ciamKeyRole"))))
    return [*(_sprawl_row(d, one(c, "ciamBindingRole"), c) for c in creds),
            *(_sprawl_row(d, role) for role in sorted(orphans) if role not in described)]


# ------------------------------------------------------------------ rotation impact
def _certificate_steps(d, c):
    """Re-issuing a certificate: the certificate, whoever presents or trusts it, the partner to coordinate with."""
    partner = follow(d, c, "ciamPartnerContact")
    users = tuple(dict.fromkeys(e.dn for attr in CERTIFICATE_USE for _, e in referrers(d, c, attr)))
    return (("re-issue certificate", one(c, "cn"), _joined(values(c, "ciamSubjectAltName")) or one(c, "ciamSubject", ""),
             owner_label(d, c)),
            *(_certificate_user(d, get(d, u)) for u in users),
            *((("coordinate with partner", rdn_value(partner), one(partner, "mail", ""), owner_label(d, c)),)
              if partner else ()))


def _certificate_user(d, e):
    if is_a(e, "ciamServiceName"):
        return ("service presents it", one(e, "ciamFqdn"), env_label(environment_of(e)), responsible(d, e))
    return ("uses the certificate", rdn_value(e), "", responsible(d, e))


def _binding_steps(d, b, holders):
    """Rotating one binding's material: where it is kept, which environments use it (an overlay shares its base's)."""
    env = environment_of(b)
    shared = [env_label(h) for h in holders if h != env]
    where = env_label(env) + (f" (shared with {', '.join(shared)})" if shared else "")
    auto = one(b, "ciamAutoRotate") == "TRUE"
    return ((("rotate (automatic)" if auto else "rotate"), one(b, "ciamRefUri"), where, responsible(d, b, get(d, env))),
            *(("update copy", uri, where, responsible(d, b, get(d, env))) for uri in values(b, "ciamCopyRef")))


def _credential_steps(d, credential, role):
    runbook = follow(d, credential, "ciamRotationRunbook") if credential else None
    carry = credential is not None and one(credential, "ciamContinuity") == "carry-over"
    reason = one(credential, "ciamContinuityReason") if credential else None
    return (*((("carry-over", "every environment receives the same new material, together"
                + (f": {reason}" if reason else ""), "", owner_label(d, credential)),) if carry else ()),
            *(step for b, holders in distinct_bindings(bindings_everywhere(d, role))
              for step in _binding_steps(d, b, holders)),
            *(("re-render setting", f"{one(f, 'cn')}: {one(s, 'ciamLocator')}", one(f, "ciamTargetRole", ""),
               responsible(d, f)) for f, s in linked_settings(d, role)),
            *(("update where used", rdn_value(e), "", responsible(d, e))
              for e in (follow_all(d, credential, "ciamUsedIn") if credential else ()) if e),
            *((("runbook", rdn_value(runbook), "", owner_label(d, runbook)),) if runbook else ()))


def rotation_impact_rows(d, dn):
    """Everything rotating a credential (or re-keying a certificate) touches: each environment's binding and other
    copies, certificates re-issued and whoever presents or trusts them, partners, linked config settings to
    re-render, places it is used, and the runbook."""
    e = get(d, dn)
    if e is None or not (is_a(e, "ciamCredential") or is_a(e, "ciamCertificate")):
        raise SystemExit(f"not a credential or certificate: {dn}")
    role = one(e, "ciamBindingRole") if is_a(e, "ciamCredential") else one(e, "ciamKeyRole")
    credential = e if is_a(e, "ciamCredential") else (credential_for_role(d, role) if role else None)
    certificates = certificates_keyed_by(d, role) if is_a(e, "ciamCredential") else (e,)
    return [*(_credential_steps(d, credential, role) if role else ()),
            *(step for c in certificates for step in _certificate_steps(d, c))]
