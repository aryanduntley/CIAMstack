"""Edge's import kinds (core.contract.ImportKind): what the cloud importers read into edge services, DNS zones,
records and forwarders, how core.inventory matches each, and the roles a new one takes when its source names none
(the same in every environment, so the planner compares them across a move). Pure.

  edge      -> ciamEdgeService      matched by provider ref (a web application firewall, a CDN, DDoS protection); a
                                    new one without a role takes '<its kind>-<role of the service it fronts>'
  zone      -> ciamDnsZoneBinding   matched by the zone's name
  record    -> ciamDnsRecord        matched by the record's name and type
  forwarder -> ciamDnsForwarder     matched by the domains it forwards
"""
from ...core.contract import ImportKind
from ...core.inventory import first_ref


def zone_role(zone):
    """The binding role a DNS zone takes when its source names none, the same in every environment."""
    return f"zone-{zone.lower().rstrip('.')}" if zone else None


def record_role(name, record_type):
    """The binding role a DNS record takes when its source names none."""
    return f"record-{record_type.lower()}-{name.lower().rstrip('.')}" if name and record_type else None


def forwarder_role(domains):
    """The binding role a DNS forwarder takes when its source names none: by the first domain it forwards."""
    first = sorted(d.lower().rstrip(".") for d in domains or () if d)
    return f"forwarder-{first[0]}" if first else None


def _names(attrs, attr):
    return tuple(sorted(v.lower().rstrip(".") for v in attrs.get(attr) or ()))


def zone_key(attrs):
    """What a DNS zone is matched by: its zone name."""
    return "|".join(_names(attrs, "ciamDnsZone")) or None


def record_key(attrs):
    """What a DNS record is matched by: its name and type."""
    return "|".join((*_names(attrs, "ciamRecordName"), *(attrs.get("ciamRecordType") or ()))) or None


def forwarder_key(attrs):
    """What a DNS forwarder is matched by: the domains it forwards."""
    return "|".join(_names(attrs, "ciamForwardDomain")) or None


def edge_role(r, roles):
    """A new edge service's role from the service it fronts ('<kind>-<service role>'), else None."""
    fronted = roles.get(first_ref(r.links.get("ciamServiceRole")))
    return f"{r.attrs['ciamEdgeKind'][0]}-{fronted}" if fronted and "ciamEdgeKind" in r.attrs else None


IMPORT_KINDS = (
    ImportKind("edge", "ciamEdgeService", ("ciamEdgeKind",), role=edge_role),
    ImportKind("zone", "ciamDnsZoneBinding", ("ciamDnsZone", "ciamZoneVisibility"), match=zone_key),
    ImportKind("record", "ciamDnsRecord", ("ciamRecordName", "ciamRecordType"), match=record_key),
    ImportKind("forwarder", "ciamDnsForwarder", ("ciamForwardDomain", "ciamForwardTarget"), match=forwarder_key),
)
ROLE_LINKS = {"ciamServiceRole": "service"}
