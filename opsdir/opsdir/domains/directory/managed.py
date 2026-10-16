"""Cloud-managed directory services (ciamManagedDirectory bindings, managed Active Directory): what each one is to the
platform and what the platform's user directory needs of one holding it, as capabilities an adapter's
ManagedDirectory descriptor says the vendor supports, doesn't support, or doesn't establish (core.managed_services).
Pure.

Target or neighbour. A binding that realizes the directory server role (ciamRealizes ds) holds the platform's user
directory in that environment; one that is the partner side of ldap integrations (ciamPartnerOf) is a directory the
platform binds to or syncs from, usually kept by another team. Its trusts with other domains are entries beneath it
(ciamDirectoryTrust).

What a target needs is read from the record: the attribute types and object classes the record defines itself (an
OID of their own: a schema extension), more than one password policy or one for a population (fine-grained password
policies), secure LDAP (ciamLdapsMode), further regions (ciamReplicaRegion) and each trust (its type and direction).
What no managed directory carries the way the record holds it: the record's base DNs (the entries land under the OU
the service lets the platform write in) and its ACIs (Active Directory grants by delegation).

Capabilities: ldap, ldaps, ldaps-internet, schema-extension, password-policies, multi-region,
trust:<forest|external>:<one-way-incoming|one-way-outgoing|two-way>.
"""
from typing import NamedTuple

from ...core.directory import children, get, norm_dn, one, rdn_value, subtree, values
from ...core.environment import environment_of, of_class
from ...core.naming import branch, env_label
from .naming import ACIS, CONSUMERS, DECLARED, DIRECTORY_SERVER_ROLE, USER_SCHEMA

MANAGED_CLASS, TRUST_CLASS = "ciamManagedDirectory", "ciamDirectoryTrust"
MANAGED_HEADERS = ("environment", "binding", "service", "as", "realizes / partner of", "domain", "edition", "regions",
                   "trusts", "kept by", "resource")
WORDS = {"ldap": "serve LDAP", "ldaps": "serve LDAP over TLS (LDAPS)",
         "ldaps-internet": "serve LDAPS to clients on the internet",
         "schema-extension": "take attribute types and object classes of the record's own (a schema extension under "
                             "their OIDs)",
         "password-policies": "apply different password policies to different users (fine-grained password policies)",
         "multi-region": "replicate to further regions"}
DIRECTIONS = {"one-way-incoming": "one-way incoming", "one-way-outgoing": "one-way outgoing", "two-way": "two-way"}

# One capability a target's record needs of the managed directory holding it: why (the record's words) and the
# entries the finding concerns.
Need = NamedTuple("Need", [("capability", str), ("cause", str), ("concerns", tuple)])


def managed_directories(m):
    """Environment m's managed directory bindings."""
    return of_class(m, MANAGED_CLASS)


def is_target(b):
    """Whether a binding holds the platform's user directory (ciamRealizes): a target, not a neighbour."""
    return one(b, "ciamRealizes") is not None


def realizes_directory(b):
    """Whether a target binding realizes the directory server role (the only one a managed directory can hold)."""
    return one(b, "ciamRealizes") == DIRECTORY_SERVER_ROLE


def partners(d, b):
    """The integrations a neighbour binding is the partner side of (those the record holds), in record order."""
    return tuple(i for i in (get(d, x) for x in values(b, "ciamPartnerOf")) if i is not None)


def trusts(d, b):
    """A managed directory's trusts (entries beneath its binding), in DN order."""
    return children(d, b.dn, TRUST_CLASS)


def trust_capability(t):
    """The capability a trust needs: trust:<type>:<direction>."""
    return f"trust:{one(t, 'ciamTrustType')}:{one(t, 'ciamTrustDirection')}"


def words(capability):
    """A capability in words: what the managed directory would have to do."""
    kind, _, rest = capability.partition(":")
    if kind == "trust":
        trust_type, _, direction = rest.partition(":")
        return f"keep a {DIRECTIONS.get(direction, direction)} {trust_type} trust"
    return WORDS.get(capability, capability)


def slug(capability):
    """A capability as a question name's part (trust:forest:two-way -> trust-forest-two-way)."""
    return capability.replace(":", "-")


def domain_dn(fqdn):
    """An Active Directory domain's DN from its DNS name (corp.example.com -> DC=corp,DC=example,DC=com)."""
    return ",".join(f"DC={label}" for label in fqdn.split("."))


def custom_schema(d):
    """The record's own user-directory attribute types and object classes: the records with an OID of their own
    (ciamLdapOid), in DN order."""
    return tuple(e for oc in ("ciamUserAttribute", "ciamUserObjectClass") for e in children(d, USER_SCHEMA, oc)
                 if one(e, "ciamLdapOid"))


def password_policies(d):
    """The record's declared password policies, in DN order."""
    return subtree(d, DECLARED, "ciamPasswordPolicy")


def _listed(entries, most=4):
    names = [f"`{one(e, 'ciamLdapName') or rdn_value(e)}`" for e in entries]
    return ", ".join(names[:most]) + (f" and {len(names) - most} more" if len(names) > most else "")


def target_needs(d, b):
    """The capabilities the record needs of the managed directory a target binding is, in order: a schema extension,
    fine-grained password policies, secure LDAP (to the internet), further regions, then each trust."""
    label, own, policies = rdn_value(b), custom_schema(d), password_policies(d)
    populated = tuple(p for p in policies if one(p, "ciamPopulation"))
    mode, regions = one(b, "ciamLdapsMode"), values(b, "ciamReplicaRegion")
    return (
        *((Need("schema-extension", f"the record defines attribute types and object classes of its own "
                                    f"({_listed(own)})", (b.dn, *(e.dn for e in own))),) if own else ()),
        *((Need("password-policies", f"the record holds {len(policies)} password policies ({_listed(policies)})"
                + (f", {_listed(populated)} for a population" if populated else ""),
                (b.dn, *(p.dn for p in policies))),) if len(policies) > 1 or populated else ()),
        *((Need("ldaps", f"`{label}` records secure LDAP (ciamLdapsMode {mode})", (b.dn,)),)
          if mode in ("private", "internet") else ()),
        *((Need("ldaps-internet", f"`{label}` records secure LDAP reachable from the internet", (b.dn,)),)
          if mode == "internet" else ()),
        *((Need("multi-region", f"`{label}` replicates to {', '.join(regions)}", (b.dn,)),) if regions else ()),
        *(Need(trust_capability(t), f"`{label}` keeps a trust with {one(t, 'ciamFqdn')}", (b.dn, t.dn))
          for t in trusts(d, b)))


def neighbour_needs(d, b):
    """The capabilities a neighbour binding needs to play its part: LDAP for each ldap integration it is the partner
    side of, then each trust."""
    label = rdn_value(b)
    return (*(Need("ldap", f"`{label}` is the partner side of `{rdn_value(i)}` ({one(i, 'ciamProtocolType')})",
                   (b.dn, i.dn)) for i in partners(d, b) if one(i, "ciamProtocolType") == "ldap"),
            *(Need(trust_capability(t), f"`{label}` keeps a trust with {one(t, 'ciamFqdn')}", (b.dn, t.dn))
              for t in trusts(d, b)))


def tls_only_consumers(d):
    """The record's directory consumers seen connecting only with TLS (ciamTlsOnly), in DN order."""
    return tuple(c for c in children(d, CONSUMERS, "ciamConsumer") if one(c, "ciamTlsOnly") == "TRUE")


def _under(dn, base):
    return norm_dn(dn) == norm_dn(base) or norm_dn(dn).endswith("," + norm_dn(base))


def moved_bases(d, base):
    """((base DN, (consumer, ...)), ...): each base DN of the record's declared backends not under the OU the platform
    writes in (base), with the consumers whose bind DN or searched subtrees name it, in record order."""
    consumers = children(d, CONSUMERS, "ciamConsumer")
    bases = tuple(dict.fromkeys(one(x, "ciamBaseDn") for x in subtree(d, DECLARED, "ciamBackend")
                                if one(x, "ciamBaseDn") and not _under(one(x, "ciamBaseDn"), base)))
    return tuple((old, tuple(c for c in consumers
                             if any(_under(v, old) for v in (*values(c, "ciamBindDn"), *values(c, "ciamSubtreeRead")))))
                 for old in bases)


def acis(d):
    """The record's ACIs, in DN order."""
    return children(d, ACIS, "ciamAci")


def managed_rows(d, dn=None):
    """One row per managed directory binding of every environment: the service, target or neighbour, what it realizes
    or is the partner of, its domain, edition, regions, trusts, who keeps it, its resource."""
    def row(b):
        keeper = get(d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
        return (env_label(environment_of(b)), rdn_value(b), one(b, "ciamManagedService"),
                "target" if is_target(b) else "neighbour",
                one(b, "ciamRealizes") or ", ".join(rdn_value(i) for i in partners(d, b)),
                one(b, "ciamFqdn") or "", one(b, "ciamDirectoryEdition") or "",
                ", ".join(x for x in (one(b, "ciamRegion"), *values(b, "ciamReplicaRegion")) if x),
                ", ".join(f"{one(t, 'ciamFqdn')} ({one(t, 'ciamTrustType')}, {one(t, 'ciamTrustDirection')})"
                          for t in trusts(d, b)),
                rdn_value(keeper) if keeper is not None else "platform", one(b, "ciamProviderRef") or "")
    return sorted(row(b) for b in subtree(d, branch("environments"), MANAGED_CLASS))
