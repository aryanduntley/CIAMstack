"""Credentials and where each environment keeps them: pure lookups over a snapshot.

A credential (ciamCredential) is joined to its bindings by role: every secret, key or certificate reference whose
ciamBindingRole is the credential's holds its material in that environment. Certificates name the role of their
private key (ciamKeyRole); captured config settings link to a binding by `role#attribute` (ciamValueFrom).
"""
import datetime as dt

from ...core.directory import children, fingerprint, get, gtime_date, is_a, one, subtree
from ...core.environment import by_role, env_model, environment_of
from ...core.naming import branch
from .naming import CERTIFICATES, CREDENTIALS

HOLDS_MATERIAL = ("ciamSecretRef", "ciamKeyRef", "ciamCertificateRef")   # binding classes that hold key material


def certificates_by_fingerprint(d):
    """{fingerprint (as the record writes it): certificate} of every certificate the record holds."""
    return {fingerprint(one(c, "ciamFingerprint")): c for c in children(d, CERTIFICATES, "ciamCertificate")}


def credentials(d):
    """Every credential, by DN."""
    return children(d, CREDENTIALS, "ciamCredential")


def credential_for_role(d, role):
    """The credential whose bindings have this role, or None."""
    return next((c for c in credentials(d) if one(c, "ciamBindingRole") == role), None)


def holds_material(b):
    return any(is_a(b, oc) for oc in HOLDS_MATERIAL)


def material_bindings(m):
    """The environment's bindings that hold key material (secret, key and certificate references)."""
    return tuple(b for b in m.bindings if holds_material(b))


def binding_for(m, credential):
    """Where the environment keeps a credential: its first material binding with the credential's role, or None."""
    return next((b for b in by_role(m, one(credential, "ciamBindingRole")) if holds_material(b)), None)


def all_material_bindings(d):
    """(environment DN, binding) for every material binding in every environment."""
    return tuple((environment_of(b), b) for b in subtree(d, branch("environments")) if holds_material(b))


def bindings_everywhere(d, role):
    """(environment DN, binding) for every environment that holds material under this role: its own binding, or the
    one it shares with the environment it is an overlay of (the same binding then appears for both)."""
    found = ((e.dn, next((b for b in by_role(env_model(d, e.dn), role) if holds_material(b)), None))
             for e in subtree(d, branch("environments"), "ciamEnvironment"))
    return tuple((env, b) for env, b in found if b is not None)


def distinct_bindings(held):
    """Each binding of (environment DN, binding) pairs once, with the environments that hold it: ((binding, (env DN,
    ...)), ...) in order of first mention."""
    first = {b.dn: b for _, b in reversed(held)}
    return tuple((first[dn], tuple(env for env, b in held if b.dn == dn)) for dn in dict.fromkeys(b.dn for _, b in held))


def certificates_keyed_by(d, role):
    """Certificates whose private key is held under this role."""
    return tuple(c for c in children(d, CERTIFICATES, "ciamCertificate") if one(c, "ciamKeyRole") == role)


def linked_settings(d, role):
    """(config file, setting) for every captured setting whose value comes from a binding with this role."""
    return tuple((get(d, s.dn.split(",", 1)[1]), s) for s in subtree(d, branch("config-files"), "ciamConfigSetting")
                 if (one(s, "ciamValueFrom") or "").split("#", 1)[0] == role)


def rotate_by(credential, binding):
    """The date the material in an environment is due for rotation (last rotated + the credential's rotation period),
    or None when either is not recorded."""
    days, last = one(credential, "ciamRotationDays") if credential else None, one(binding, "ciamLastRotated")
    return gtime_date(last) + dt.timedelta(days=int(days)) if days and last else None
