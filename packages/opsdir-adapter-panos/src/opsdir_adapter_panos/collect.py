"""PAN-OS collector (`opsdir collect`, core.contract Collector): the running configuration panos/running-config reads,
from the XML API, read-only. Pure: the core makes the requests.

Where to read is the environment's collection source for panos/running-config (ciamCollectionSource: ciamSourceRef the
Panorama's or firewall's https://<management address>, the address of one of the environment's network-firewall
appliances), with the API key its ciamCredentialRole binding references (ciamCredentialScheme api-key: sent in the
X-PAN-KEY header, never in the URL; minted outside opsdir with type=keygen for a read-only administrator, short-lived)
and the CA certificate its ciamCaRole binding references as the trust anchor. Each part of the appliance's scope and of
shared (running.py's families), and of the scopes the external allowlists on that appliance name, is one
GET /api/?type=config&action=show&xpath=<xpath>: action=show reads the RUNNING configuration (action=get would read the
candidate); nothing is ever set, edited or committed. The xpaths are reconstructed from Palo Alto's documented
examples: confirm them in the appliance's /api/ browser."""
from urllib.parse import quote

from opsdir.core.contract import Collector, Request
from opsdir.core.directory import one, rdn_value
from opsdir.domains.governance.collection import collection_sources, readable_sources
from opsdir.domains.infrastructure.appliances import appliances
from opsdir.domains.infrastructure.running import allowlist_refs
from .importer import ADAPTER, STACK_ROLE, allowlist_place, management_host, placement
from .running import API, OBJECTS, SHARED, xpath

IMPORTER = "panos/running-config"
SCHEME = "api-key"                  # the collection source's ciamCredentialScheme: the secret alone, in a header
KEY_HEADER = "X-PAN-KEY"            # where PAN-OS takes the API key
SHOW = "type=config&action=show"    # the running configuration; never action=get (candidate) and never a commit


def credential(s):
    """The Request credential sending source s's API key in X-PAN-KEY (scheme api-key: no login), or None."""
    return (SCHEME, s.credential, None, KEY_HEADER) if s.credential else None


def families(scope, kind):
    """The families read of one scope of an appliance of kind panorama or firewall."""
    rules = ("pre-rulebase", "post-rulebase") if kind == "panorama" else ("rulebase",) if scope != SHARED else ()
    return (*rules, *OBJECTS)


def _parts(m, a):
    """((scope, family), ...) read for appliance a: its scope and shared, and the scopes allowlists on it name."""
    kind, own, _, _ = placement(a)
    named = [p[1] for _, path in allowlist_refs(m.d, ADAPTER) for p in (allowlist_place(path),)
             if p and p[0] == management_host(one(a, "ciamManagementAddress"))]
    scopes = dict.fromkeys((own, SHARED, *named))
    return tuple((s, f) for s in scopes for f in families(s, "panorama" if s.startswith("device-group/")
                                                              or (s == SHARED and kind == "panorama") else kind))


def _appliance(m, s):
    return next((a for a in appliances(m, STACK_ROLE) if s.locations
                 and management_host(one(a, "ciamManagementAddress")) == management_host(s.locations[0])), None)


def running_steps(d, m, done, options):
    """One request per part of each collection source's appliance (its first location)."""
    return tuple((f"{m.label}/{rdn_value(a)}/{API}{scope}/{family}.xml",
                  Request(f"{s.locations[0].rstrip('/')}/api/?{SHOW}&xpath={quote(xpath(scope, family), safe='')}",
                          (), credential(s), s.ca))
                 for s in readable_sources(m, IMPORTER, (SCHEME,))
                 for a in (_appliance(m, s),) if a is not None for scope, family in _parts(m, a))


def source_problems(d, m, options):
    """Why the collection sources can't be read: an unbound credential or trust anchor, no location, another
    credential scheme, or a location that is none of the environment's network firewalls."""
    return tuple(p for s in collection_sources(m, IMPORTER) for p in (
        *s.problems,
        *((f"collection source `{s.name}`: credential scheme `{s.scheme}`: PAN-OS takes an API key ({SCHEME}, "
           f"sent as {KEY_HEADER})",) if s.scheme != SCHEME else ()),
        *((f"collection source `{s.name}`: {s.locations[0]} is none of {m.label}'s network firewalls "
           f"(ciamAppliance, stack role {STACK_ROLE}, ciamManagementAddress)",)
          if s.locations and _appliance(m, s) is None else ())))


COLLECTORS = (Collector("running-config", "environment", running_steps, problems=source_problems),)
