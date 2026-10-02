"""PingFederate plugin instances: password credential validators, IdP adapters, authentication selectors, access
token managers, notification publishers and CAPTCHA providers, read from the Admin API into the record and rendered
back for each environment. Pure.

One pingfedPlugin entry per instance (cn: its id) under its kind's branch: the plugin it is (pluginDescriptorRef, as
pingfedPluginType), the instance it inherits from (parentRef, as pingfedParent), the objects its settings name
(pingfedUses: a validator's data store, an HTML form adapter's validators, the adapters a composite adapter chains, the
certificates of the key pairs a JWT token manager signs with) and
its settings as the Admin API writes them, with what may be secret withheld (opsdir_adapter_pingfederate.withheld):
each environment renders the reference of the instance's credential role there. What the record adds to an instance
(its credential role, owners) is kept on import, and the rendered files import back unchanged.
"""
import json
from types import MappingProxyType
from typing import NamedTuple

from opsdir.core.directory import children, get, make_entry, merged_attrs, one, rdn_value
from opsdir.core.jsondata import canonical, held_json
from opsdir.core.naming import rdn_safe
from .naming import (CAPTCHA_PROVIDERS, IDP_ADAPTERS, NOTIFICATION_PUBLISHERS, SELECTORS, TOKEN_MANAGERS, VALIDATORS,
                     named)
from .objects import NOT_EXPORTED, links, why_unresolved
from .withheld import filled, withheld_settings

Kind = NamedTuple("Kind", [("resource", str), ("base", str), ("output", str), ("label", str)])
KINDS = MappingProxyType({
    "validator": Kind("/passwordCredentialValidators", VALIDATORS, "password-credential-validators.json",
                      "password credential validator"),
    "idp-adapter": Kind("/idp/adapters", IDP_ADAPTERS, "idp-adapters.json", "IdP adapter"),
    "selector": Kind("/authenticationSelectors", SELECTORS, "authentication-selectors.json", "authentication selector"),
    "access-token-manager": Kind("/oauth/accessTokenManagers", TOKEN_MANAGERS, "access-token-managers.json",
                                 "access token manager"),
    "notification-publisher": Kind("/notificationPublishers", NOTIFICATION_PUBLISHERS, "notification-publishers.json",
                                   "notification publisher"),
    "captcha-provider": Kind("/captchaProviders", CAPTCHA_PROVIDERS, "captcha-providers.json", "CAPTCHA provider")})
# settings fields whose value is another PingFederate object's id, by the field's name (PingFederate's own plugins;
# verify against the target version, and add a custom plugin's fields here)
REF_FIELDS = MappingProxyType({"Password Credential Validator Instance": "validator", "LDAP Datastore": "datastore",
                               "JDBC Datastore": "datastore", "Adapter Instance": "idp-adapter",
                               "Certificate": "key-pair"})    # a JWT token manager's signing key pairs (Certificates)
OWNED = ("cn", "pingfedPluginKind", "pingfedPluginType", "pingfedParent", "pingfedUses", "pingfedConfig",
         "pingfedWithheld")


def settings_fields(settings):
    """Every settings field: the plain ones and those in the rows of its tables."""
    c = settings.get("configuration") if isinstance(settings.get("configuration"), dict) else {}
    rows = (r for t in c.get("tables") or () if isinstance(t, dict) for r in t.get("rows") or () if isinstance(r, dict))
    return tuple(f for f in (*(c.get("fields") or ()), *(f for r in rows for f in r.get("fields") or ()))
                 if isinstance(f, dict))


def field_refs(settings):
    """(kind, id) of the objects an instance's settings fields name, each once."""
    return tuple(dict.fromkeys((REF_FIELDS[f["name"]], f["value"]) for f in settings_fields(settings)
                               if f.get("name") in REF_FIELDS and isinstance(f.get("value"), str) and f["value"]))


def plugin_refs(kind, settings):
    """(kind, id) of every object an instance names: the instance it inherits from, then its fields'."""
    parent = (settings.get("parentRef") or {}).get("id")
    return (*(((kind, parent),) if parent else ()), *field_refs(settings))


# ------------------------------------------------------------------ import
def plugin_entry(d, kind, item, patterns, exported):
    """(DN, entry, notices) for one exported plugin instance, or (None, None, notices) when its id can't name one."""
    pid, k = item.get("id"), KINDS[kind]
    label = f"{k.label} {item.get('name') or pid}"
    if not rdn_safe(pid or ""):
        return None, None, (f"{label}: its id can't name an entry, not imported",)
    config, held = withheld_settings({key: v for key, v in item.items() if key not in ("id", "pluginDescriptorRef")},
                                     patterns)
    parent = (item.get("parentRef") or {}).get("id")
    parents, lost_parent = links(d, ((kind, parent),) if parent else (), exported)
    uses, lost = links(d, field_refs(item), exported)
    dn = named(k.base, pid)
    owned = {"cn": (pid,), "pingfedPluginKind": (kind,),
             "pingfedPluginType": ((item.get("pluginDescriptorRef") or {}).get("id") or "unknown",),
             "pingfedParent": parents[:1] or (None,), "pingfedUses": uses, "pingfedConfig": (canonical(config),),
             "pingfedWithheld": held}
    entry = make_entry(dn, ("top", "ciamObject", "pingfedPlugin"), merged_attrs(get(d, dn), owned, OWNED))
    return dn, entry, (*(f"{label}: names {why_unresolved(d, rk, ri, NOT_EXPORTED)}"
                         for rk, ri in (*lost_parent, *lost)),
                       *((f"{label}: its secrets are withheld; set pingfedCredentialRole to the secret role that holds "
                          "them",) if held and not one(entry, "pingfedCredentialRole") else ()))


def plugin_groups(d, found, patterns, exported):
    """(groups, notices): an entry for every plugin instance of the export ({kind: items})."""
    parts = [plugin_entry(d, kind, item, patterns, exported) for kind in KINDS for item in found.get(kind, ())]
    return tuple((dn, (e,)) for dn, e, _ in parts if dn), tuple(n for _, _, ns in parts for n in ns)


# ------------------------------------------------------------------ render
def plugin_view(m, entry):
    """A plugin instance as the Admin API takes it, for environment m (withheld values from its credential role)."""
    return {"id": rdn_value(entry), "pluginDescriptorRef": {"id": one(entry, "pingfedPluginType")},
            **filled(m, entry, held_json(entry, "pingfedConfig"))}


def plugin_files(m):
    """{pingfederate/<kind file>: text} for every kind of plugin instance environment m's record has."""
    held = {kind: children(m.d, k.base, "pingfedPlugin") for kind, k in KINDS.items()}
    return {f"pingfederate/{KINDS[kind].output}": json.dumps([plugin_view(m, e) for e in entries], indent=2) + "\n"
            for kind, entries in held.items() if entries}
