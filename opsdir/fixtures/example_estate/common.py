"""Shared names and builders for the Example Aero synthetic estate (a showcase and test fixture).

Everything is fictional: company "Example Aero", partners "Skyline Air" and "Harbor MRO", documentation IP
ranges (RFC 5737), the AWS documentation account 111122223333, and made-up resource ids.
"""
import hashlib
from typing import NamedTuple

R = "dc=ciam-ops"
USERS = "dc=partners,dc=example-aero,dc=test"          # base DN of the (fictional) user directory
PEOPLE = f"ou=people,{USERS}"

ENVS = f"ou=environments,{R}"
AWS = f"env=prod,cloud=source,{ENVS}"
AZ = f"env=prod,cloud=target,{ENVS}"
DECL = f"ou=declared,ou=config,{R}"
OBS = f"ou=observed,ou=config,{R}"
OWN = f"ou=owners,{R}"
CHG = f"ou=changes,{R}"
US = f"ou=user-schema,{R}"
CON = f"ou=consumers,{R}"
ACI = f"ou=acis,{R}"
RB = f"ou=runbooks,{R}"
CERTS = f"ou=certificates,{R}"
INTS = f"ou=integrations,{R}"
XA = f"ou=external-allowlists,{R}"
INC = f"ou=incidents,{R}"

# One entry to write: the data file it belongs to, and the entry itself (attrs: {name: [str, ...]}).
Spec = NamedTuple("Spec", [("file", str), ("dn", str), ("classes", tuple), ("attrs", dict)])


def spec(file, dn, classes, **attrs):
    """An entry spec; None-valued attributes are dropped, every value becomes a string."""
    clean = {k: [str(x) for x in v] if isinstance(v, (list, tuple)) else [str(v)]
             for k, v in attrs.items() if v is not None}
    return Spec(file, dn, tuple(classes), clean)


def ou(file, name, parent=R, desc=None):
    return spec(file, f"ou={name},{parent}", ["top", "organizationalUnit"], ou=name, description=desc)


def t(date, hms="000000"):
    """GeneralizedTime from an ISO date."""
    return date.replace("-", "") + hms + "Z"


def fp(name):
    """Deterministic fake SHA-256 fingerprint for a certificate name."""
    h = hashlib.sha256(name.encode()).hexdigest().upper()
    return ":".join(h[i:i + 2] for i in range(0, 64, 2))


def owner(*names):
    return [f"cn={n},{OWN}" for n in names]


def chg(c):
    return f"cn={c},{CHG}"


def ua(*names):
    return [f"cn={n},{US}" for n in names]


def cert(*names):
    return [f"cn={n},{CERTS}" for n in names]
