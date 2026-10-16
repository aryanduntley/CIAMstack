"""SiteMinder's XPSExport XML as plain objects, and every XPS name the adapter reads, as data. Pure.

UNVERIFIED FOR 12.8 / 12.9: the layout and the class and property names below come from Broadcom's archived 12.51
XPS reference (XPSDeployment / XPSPolicyData schemas, XPSExport options) and knowledge-base articles quoting 12.8
exports (the <XPS>/<PolicyData>/<Object Class Xid>/<Property Name> shape, CA.SM::AgentConfig, CA.SM::Realm,
CA.FED::SPPartnership, ...). Where those don't name a property, the name here is the adapter's reading of the
documented shape. The parsing code reads names only through these tables, so a real export that names them otherwise
is fixed here, in one place (README, Known limits: the acceptance items).

  <XPS ...>
    <PolicyData>
      <Object Class="CA.SM::Domain" Xid="CA.SM::Domain@03-...">
        <Property Name="CA.SM::Domain.Name"><StringValue>Crew Portal</StringValue></Property>
        <Object Class="CA.SM::Realm" Xid="CA.SM::Realm@06-...">        child objects nest in their parent
          <Property Name="CA.SM::Realm.AgentLink"><LinkValue><XID>CA.SM::Agent@01-...</XID></LinkValue></Property>
          <Property Name="CA.SM::Realm.AuthSchemeLink"><XREF>Ref1</XREF></Property>      resolved through
        ...                                              <ReferenceValue ReferenceId="Ref1"><LinkValue>...
A property is named by its qualified name (class, then property); it may be declared on a base class, so only the
part after the last dot is read. Values are the text of any *Value element (StringValue, NumberValue,
BooleanValue, ...); links are the XIDs of LinkValue elements and of the ReferenceValues an XREF names.
"""
import re
from types import MappingProxyType
from typing import NamedTuple, Optional

# The XPS classes the adapter maps, by kind (a class not listed is kept as a source object to review)
KINDS = MappingProxyType({
    "CA.SM::Domain": "domain", "CA.SM::Realm": "realm", "CA.SM::Rule": "rule", "CA.SM::Policy": "policy",
    "CA.SM::PolicyLink": "policy-link", "CA.SM::UserPolicy": "user-policy", "CA.SM::Response": "response",
    "CA.SM::ResponseAttr": "response-attr", "CA.SM::UserDirectory": "user-directory",
    "CA.SM::AuthScheme": "auth-scheme", "CA.SM::Agent": "agent", "CA.SM::AgentConfig": "aco",
    "CA.SM::HostConfig": "hco", "CA.SM::TrustedHost": "trusted-host", "CA.SM::AgentInstance": "agent-instance",
    "CA.SM::PasswordPolicy": "password-policy", "CA.SM::SAMLv2SP": "runtime-sp",
    "CA.FED::SPPartnership": "sp-partnership", "CA.FED::IDPPartnership": "idp-partnership",
    "CA.FED::OIDCClient": "oidc-client", "CA.FED::OIDCAdminConfig": "oidc-provider",
    "CA.FED::Certificate": "certificate", "CA.SM::Admin": "admin"})

# The properties read of each kind: field -> the property's name (the part after the class)
FIELDS = MappingProxyType({
    "domain": {"name": "Name", "description": "Desc"},
    "realm": {"name": "Name", "filter": "ResourceFilter", "agent": "AgentLink", "scheme": "AuthSchemeLink",
              "idle": "IdleTimeout", "max": "MaxTimeout"},
    "rule": {"name": "Name", "resource": "Resource", "regex": "IsRegex", "actions": "Actions",
             "allow": "AllowAccess", "enabled": "IsEnabled"},
    "policy": {"name": "Name", "enabled": "IsEnabled"},
    "policy-link": {"rule": "RuleLink", "response": "ResponseLink"},
    "user-policy": {"directory": "UserDirectoryLink", "path": "FilterPath", "kind": "FilterClass"},
    "response": {"name": "Name"},
    "response-attr": {"type": "AgentTypeAttr", "value": "Value"},
    "user-directory": {"name": "Name", "namespace": "NameSpace", "servers": "Server", "bind": "Username",
                       "tls": "Secure"},
    "auth-scheme": {"name": "Name", "type": "Type", "level": "Level", "library": "Library"},
    "agent": {"name": "Name", "type": "AgentType"},
    "sp-partnership": {"name": "Name", "local": "LocalEntityID", "remote": "RemoteEntityID",
                       "base_url": "LocalBaseURL", "acs": "AssertionConsumerServiceURL", "binding": "ACSBinding",
                       "nameid": "NameIDFormat", "attributes": "AssertionAttribute", "certificate": "CertificateLink",
                       "active": "IsActive"},
    "idp-partnership": {"name": "Name", "local": "LocalEntityID", "remote": "RemoteEntityID",
                        "base_url": "LocalBaseURL", "sso": "SSOServiceURL", "binding": "SSOBinding",
                        "nameid": "NameIDFormat", "certificate": "CertificateLink", "active": "IsActive"},
    "oidc-client": {"name": "Name", "client_id": "ClientID", "redirects": "RedirectURI", "grants": "GrantType",
                    "scopes": "Scope", "auth": "ClientAuthMethod"},
    "certificate": {"alias": "Alias", "fingerprint": "SHA256Fingerprint"},
    "runtime-sp": {"partnership": "PartnershipLink"},
})
NAME = "Name"                     # what any object is called (the classes above that have one)
VERSION_ATTRIBUTES = ("ProductVersion", "Version")    # where the root <XPS> element may say the release it is from

# Response attributes that are an HTTP header (the standard header contract) or a cookie (no standard equivalent)
HEADER_RESPONSE = "WebAgent-HTTP-Header-Variable"
COOKIE_RESPONSE = "WebAgent-HTTP-Cookie-Variable"
# what an agent's type says about where it runs (first match, case-insensitive; else a web agent)
GATEWAY_TYPES = ("sps", "access gateway", "secure proxy")
# an authentication scheme whose type says it runs the operator's own library
CUSTOM_SCHEME = "custom"

# Sensitive settings: never read into the record, clear (an -npass export) or encrypted (-pass). A property is
# withheld when its name matches SENSITIVE (whatever its class: the per-class list isn't published), when its value
# looks encrypted (ENCRYPTED: a {cipher} prefix, a shape seen in SiteMinder's tools, unverified for XPS) or when the
# store's secret patterns match it.
SENSITIVE = re.compile(r"password|secret|passphrase|private.?key|credentials?value", re.IGNORECASE)
ENCRYPTED = re.compile(r"^\{[A-Za-z0-9_-]{2,16}\}")
PURPOSES = MappingProxyType({
    "Password": "the bind password of the connection",
    "SharedSecret": "the shared secret an agent or trusted host signs its requests with",
    "Secret": "a secret the object is configured with",
    "ClientSecret": "the client's secret",
    "BackchannelPassword": "the password of the partnership's back channel"})
GENERIC_PURPOSE = "a sensitive setting"

Obj = NamedTuple("Obj", [("cls", str), ("xid", str), ("props", tuple), ("links", tuple), ("parent", Optional[str]),
                         ("children", tuple)])


def _tag(e):
    return e.tag.rsplit("}", 1)[-1]


def _local(name):
    return (name or "").rsplit(".", 1)[-1]


def _texts(prop):
    """The values of a property: the text of each *Value element that isn't a link."""
    return tuple((x.text or "").strip() for x in prop.iter() if _tag(x).endswith("Value")
                 and _tag(x) not in ("LinkValue", "ReferenceValue") and (x.text or "").strip())


def _xids(e):
    return tuple((x.text or "").strip() for x in e.iter() if _tag(x) == "XID" and (x.text or "").strip())


def _links(prop, refs):
    """The XIDs a property links to: its LinkValues', and those of the ReferenceValues its XREFs name."""
    direct = tuple(x for v in prop.iter() if _tag(v) == "LinkValue" for x in _xids(v))
    via = tuple(x for v in prop.iter() if _tag(v) == "XREF" for r in (refs.get((v.text or "").strip()),)
                if r is not None for x in _xids(r))
    return (*direct, *via)


def _properties(obj):
    return tuple(p for p in obj if _tag(p) == "Property")


def _grouped(pairs):
    """((name, values), ...) with the values of properties of one name together, first appearance first."""
    names = tuple(dict.fromkeys(n for n, _ in pairs))
    return tuple((n, tuple(v for m, vs in pairs if m == n for v in vs)) for n in names)


def _objects(e, refs, parent=None):
    """Every Object element below e, depth first, with its parent's XID."""
    found = ()
    for o in (x for x in e if _tag(x) == "Object"):
        xid = o.get("Xid") or o.get("XID") or ""
        props = _grouped(tuple((_local(p.get("Name")), _texts(p)) for p in _properties(o) if _texts(p)))
        links = _grouped(tuple((_local(p.get("Name")), _links(p, refs)) for p in _properties(o) if _links(p, refs)))
        kids = _objects(o, refs, xid)
        own = tuple(k.xid for k in kids if k.parent == xid)
        found = (*found, Obj(o.get("Class") or "", xid, props, links, parent, own), *kids)
    for x in (x for x in e if _tag(x) != "Object" and _tag(x) != "Property"):
        found = (*found, *_objects(x, refs, parent))
    return found


def export_objects(root):
    """(objects in document order, the release the export says it is from or None) of a parsed XPSExport document."""
    refs = {r.get("ReferenceId"): r for r in root.iter() if _tag(r) == "ReferenceValue" and r.get("ReferenceId")}
    version = next((root.get(a) for a in VERSION_ATTRIBUTES if root.get(a)), None)
    return _objects(root, refs), version


def kind(o):
    """The kind the adapter maps an object to (KINDS), or None (kept as a source object to review)."""
    return KINDS.get(o.cls)


def field_name(k, field):
    """The property a field of kind k is read from (any kind's name: NAME; a field the table doesn't list: itself)."""
    return FIELDS.get(k, {}).get(field, NAME if field == "name" else field)


def values_of(o, field):
    """The values of an object's field (FIELDS of its kind; a property name for kinds the table doesn't list)."""
    want = field_name(kind(o), field)
    return next((v for n, v in o.props if n == want), ())


def value_of(o, field):
    found = values_of(o, field)
    return found[0] if found else None


def links_of(o, field):
    want = field_name(kind(o), field)
    return next((v for n, v in o.links if n == want), ())


def link_of(o, field):
    found = links_of(o, field)
    return found[0] if found else None


def name(o):
    """What an object is called: its Name, else the part of its XID after the class."""
    return value_of(o, "name") or o.xid.split("@", 1)[-1]


def is_true(v):
    return (v or "").strip().lower() in ("true", "yes", "1")


def sensitive(prop, vals, patterns, scan):
    """Whether a property is withheld: its name is a sensitive one, or a value looks encrypted or like secret
    material to the store (scan: core.secrets.scan)."""
    return bool(SENSITIVE.search(prop)) or any(ENCRYPTED.match(v) or scan(v, patterns) for v in vals)


def purpose(prop):
    """What a withheld setting is, in words."""
    return PURPOSES.get(prop) or next((p for k, p in PURPOSES.items() if prop.endswith(k)), GENERIC_PURPOSE)
