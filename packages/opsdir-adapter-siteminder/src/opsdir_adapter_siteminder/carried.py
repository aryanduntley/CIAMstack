"""What SiteMinder holds that the standard model has no equivalent for, carried as source objects (core governance:
ciamSourceObject under ou=siteminder,ou=source-objects): what each is, the server role holding it, how it is handled
when SiteMinder is retired and whether a move waits for that. Pure.

  agent configuration objects (ACOs)   rebuild        the agent settings become the target gateway's or agent's
  host configuration objects (HCOs)    retire         agents' list of policy servers: nothing in the target uses it
  trusted hosts, agent instances       re-register /  each web server registers anew with what protects it
                                       retire
  password policies                    review         their rules and the password history kept in the directory
  administrators and their rights      review         re-created in the target's own admin model
  OpenID provider configuration        rebuild        the target's OpenID provider takes its settings
  custom authentication schemes        rebuild, a     the operator's own sign-on code
                                       move waits
  cookie and other responses           rebuild /      the target gateway's identity mapping
                                       review
  an Access Gateway's routing          rebuild, a     its proxy rules aren't in the policy store (dropped once the
                                       move waits     record holds the gateway's routes: routing.py)
  the keys                             re-provision   agent and session keys (smkeyexport) and federation keys (the
                                                      certificate data store) are never in an XPSExport
  any class this adapter doesn't map   review
The ACO's source object also keeps its settings (smConfig): what the agents' settings are read from (agents.py). The
agent files make an ACO, an HCO and a trusted host concern the servers whose files name them (agents.file_concerns).
"""
from types import MappingProxyType

from opsdir.core.directory import get, gtime, rdn_of
from .entries import config, entry, facts
from .naming import ACCESS_GATEWAY, AGENT, POLICY_SERVER
from .responses import header_value, parts
from .xps import name

# kind of source object -> (handling, the role holding it, whether a move waits for it, how)
CARRY = MappingProxyType({
    "aco": ("rebuild", AGENT, False,
            "the agent settings it holds (cookie domain, logout, ignored extensions, URL checks, caching) become the "
            "settings of the gateway or agent that protects these resources in the target"),
    "hco": ("retire", AGENT, False,
            "it tells agents which policy servers to ask; the target's gateways and agents find their own policy "
            "decision point, nothing carries over"),
    "trusted-host": ("re-register", AGENT, False,
                     "the web server registers anew with whatever protects it in the target; its shared secret is "
                     "not carried"),
    "agent-instance": ("retire", AGENT, False, "an agent's registration record: nothing carries over"),
    "password-policy": ("review", POLICY_SERVER, False,
                        "its rules, and the password history it keeps in the user directory (encrypted with the "
                        "policy store's session key), don't carry over: decide which target product enforces them"),
    "admin": ("review", POLICY_SERVER, False,
              "administrators and their rights are re-created in the target's own admin model; no credential "
              "carries over"),
    "oidc-provider": ("rebuild", POLICY_SERVER, False,
                      "the target's OpenID provider takes over its settings (claims, signing); its clients are "
                      "integrations already"),
    "custom-scheme": ("rebuild", POLICY_SERVER, True,
                      "its library runs the operator's own sign-on code: rebuild that sign-on in the target's "
                      "federation or access product before the realms using it move"),
    "cookie": ("rebuild", AGENT, False,
               "set the cookie from the identity mapping of the gateway that protects the realm in the target"),
    "response": ("review", AGENT, False,
                 "a response with no standard equivalent: rebuild what it does in the target's gateway, or drop it"),
    "routing": ("rebuild", ACCESS_GATEWAY, True,
                "its proxy rules (proxyrules.xml on the gateway, not in the policy store) route requests to the "
                "applications: rebuild them as the target gateway's routes, then import them for the record"),
    "keys": ("re-provision", POLICY_SERVER, False,
             "agent keys and the session key (smkeyexport) and federation keys (the certificate data store, "
             "smkeytool) are never in an XPSExport: the target makes its own, and partners are given its new "
             "certificates"),
    "unknown": ("review", POLICY_SERVER, False, "an object this adapter doesn't map: find what depends on it"),
})
KEYS_CLASS = "SiteMinder key store"      # the source class of the keys' source object (no XPS object holds them)


def carried_name(k, o):
    """What a source object is called before it is made unique: its kind and its SiteMinder name."""
    return f"{k}-{name(o)}" if o is not None else k


def _response_facts(a):
    kind, head, expr = parts(a)
    _, value, held = header_value(expr)
    return (f"AgentTypeAttr {kind}", f"Name {head}", f"Value {'withheld' if held else value}")


def carried_entry(d, x, k, o, dn, at, concerns=()):
    """The source object of kind k for object o (None: the keys), at dn; once recorded, its handling (how, whether a
    move waits) is the record's: a re-import keeps it."""
    handling, role, blocks, how = CARRY[k]
    decided = {} if get(d, dn) is not None else {"ciamHandling": (handling,), "ciamHow": (how,),
                                                 "ciamBlocking": ("TRUE" if blocks else None,)}
    found = (_response_facts(o) if k in ("cookie", "response") else facts(x, o)) if o is not None else (
        "AgentKeys smkeyexport", "SessionKey smkeyexport", "FederationKeys certificate data store")
    sm = {"smXid": (o.xid,), "smClass": (o.cls,), "smConfig": (config(x, o) if k == "aco" else None,),
          "smWithheld": x.withheld[o.xid]} if o is not None else {}
    return entry(d, dn, ("top", "ciamObject", "ciamSourceObject", *(("smObject",) if o is not None else ())),
                 {"cn": (rdn_of(dn),), "ciamSourceClass": (o.cls if o is not None else KEYS_CLASS,),
                  "ciamTargetRole": (role,), "ciamSourceFact": found or (None,), **decided,
                  "ciamConcerns": tuple(concerns) or (None,), "ciamImportedAt": (gtime(at) if at else None,), **sm})
