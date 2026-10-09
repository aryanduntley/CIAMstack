"""PingFederate resources held as is: every resource of the Admin API bulk export the adapter doesn't model
(/serverSettings, /oauth/accessTokenMappings, token processors and generators, ...) is kept item by item,
as the Admin API writes it, so nothing the export holds is left out. Pure.

  ou=<resource type, '/' as '.'>,ou=resources,ou=pingfederate     one container per resource type
    cn=<the item's id>                                            pingfedResource: pingfedResourceType, its settings
                                                                  (pingfedConfig, secrets withheld), credential role
  (a resource that is one object, with no id: cn=settings; items without an id: cn=item-<n>)

A resource type is imported as one group: an item the export no longer has is removed. Each environment renders them
back as Admin API requests (opsdir_adapter_pingfederate.admin_api), with withheld values from the item's credential
role, so a render imports back through the same importer unchanged.
"""
from opsdir.core.directory import children, get, make_entry, merged_attrs, one, ou_entry, rdn_value
from opsdir.core.jsondata import canonical, held_json
from opsdir.core.naming import rdn_safe
from .naming import RESOURCES, named

from .withheld import filled, withheld_settings

OUTPUT = "pingfederate/other-resources.json"
OWNED = ("cn", "pingfedResourceType", "pingfedConfig", "pingfedWithheld")


def type_slug(resource_type):
    """A resource type as an RDN value: /oauth/accessTokenMappings -> oauth.accessTokenMappings."""
    return resource_type.strip("/").replace("/", ".")


def _item_name(item, n, single):
    named_by = item.get("id") if isinstance(item.get("id"), str) else None
    return named_by or ("settings" if single else f"item-{n}")


def resource_group(d, resource_type, items, patterns):
    """((container DN, entries), notices): a resource type's items held as is."""
    slug = type_slug(resource_type)
    if not rdn_safe(slug):
        return None, (f"{resource_type}: its name can't name an entry; not held",)
    base = f"ou={slug},{RESOURCES}"
    names = [_item_name(i, n, len(items) == 1) for n, i in enumerate(items)]
    usable = [(name, i) for name, i in zip(names, items) if rdn_safe(name) and names.count(name) == 1]

    def entry(name, item):
        config, held = withheld_settings(item, patterns)
        dn = named(base, name)
        owned = {"cn": (name,), "pingfedResourceType": (resource_type,), "pingfedConfig": (canonical(config),),
                 "pingfedWithheld": held}
        return make_entry(dn, ("top", "ciamObject", "pingfedResource"), merged_attrs(get(d, dn), owned, OWNED))
    entries = [entry(name, i) for name, i in usable]
    container = get(d, base) or ou_entry(base)
    return (base, (container, *entries)), \
        (*(f"{resource_type}: an item named {name!r} can't name an entry, or another has the name; not held"
           for name, i in zip(names, items) if (name, i) not in usable),
         *(f"{resource_type} {one(e, 'cn')}: its secrets are withheld; set pingfedCredentialRole to the secret role "
           f"that holds them" for e in entries if one(e, "pingfedWithheld") and not one(e, "pingfedCredentialRole")))


def resource_groups(d, unread, patterns):
    """(groups, notices) for every resource type of the export the adapter doesn't model ({type: items})."""
    built = [resource_group(d, t, items, patterns) for t, items in sorted(unread.items())]
    return (tuple(g for g, _ in built if g),
            (*((f"held as is (not modeled): {', '.join(f'{t} ({len(i)})' for t, i in sorted(unread.items()))}",)
               if unread else ()), *(n for _, ns in built for n in ns)))


def held_resources(d):
    """The resources held as is, by container (resource type)."""
    return tuple(r for c in children(d, RESOURCES, "organizationalUnit")
                 for r in children(d, c.dn, "pingfedResource"))


def resource_body(m, r):
    """A resource held as is, as the Admin API takes it, for environment m (withheld values from its credential role)."""
    return filled(m, r, held_json(r, "pingfedConfig"))


def resource_label(r):
    return f"Resource `{one(r, 'pingfedResourceType')} {rdn_value(r)}`"
