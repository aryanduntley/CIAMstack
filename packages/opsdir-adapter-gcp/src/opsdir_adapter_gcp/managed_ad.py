"""Google Cloud's Managed Service for Microsoft Active Directory as a cloud-managed directory service (core directory
domain: ciamManagedDirectory, flow 76): what the planner knows of it (the ManagedDirectory descriptor, from Google's
documentation, research note 3196, read 2026-10-16), its Terraform render and its read back. Pure.

A target binding (ciamManagedService google-managed-ad, ciamRealizes ds) is rendered, stamped with its entry:

  google_active_directory_domain    the domain (its name, the regions it runs in: ciamRegion and ciamReplicaRegion, the
                                    reserved range ciamCidr, the environment's network authorized), deletion protection
                                    on, labelled with its role and the role it realizes

The google provider takes no administrator password for it (Google sets the delegated administrator's by its API),
and google_active_directory_domain_trust's handshake secret would be in Terraform state: trusts are actions, as are
secure LDAP's certificate, schema extensions and the predefined password policies' settings. Assured Workloads lists
it in no control package (its supported products: "not listed ... unsupported"): the planner blocks it in an
environment whose required authorization level asks for one (the partition assured:<regime>). A neighbour isn't the
platform's to render: a note. Read back from Terraform state: the domain's name, regions and reserved range.
"""
from itertools import chain

from opsdir.core.contract import ManagedDirectory
from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import of_class, recorded
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.directory.managed import (custom_schema, domain_dn, is_target, password_policies,
                                              realizes_directory, trust_summary, trusts)
from opsdir_format_terraform.hcl import comment, from_entry, ref, tf_block, tf_name
from .account import REGIMES, level_regime
from .names import binding_labels, label, label_tags

SERVICE = "google-managed-ad"
AREA = "Directory"
PUBLIC = "public"

# ------------------------------------------------------------------ what Google documents (read 2026-10-16)
_GUIDE = "Managed Service for Microsoft AD documentation (2026-10)"
_ASSURED = ("not among the Assured Workloads supported products of {} (\"If a service is not listed for a given "
            "control package, that service is unsupported\", 2026-10)")
_FOREST = f"one-way and two-way forest trusts ({_GUIDE}: create a trust)"


def partition(m):
    """Where environment m's Google Cloud resources run, as far as the managed directory goes: assured:<regime> when
    its required authorization level asks for an Assured Workloads package (IL5, IL4, FEDRAMP_HIGH, FEDRAMP_MODERATE,
    IL2), else public."""
    regime = level_regime(m)
    return f"assured:{regime}" if regime else PUBLIC


GOOGLE_MANAGED_AD = ManagedDirectory(
    name=SERVICE, title="Managed Service for Microsoft Active Directory", partition=partition,
    available={PUBLIC: _GUIDE},
    absent={f"assured:{regime}": _ASSURED.format(regime) for _, regime in REGIMES},
    supported={
        "ldap": f"Microsoft Active Directory run by Google ({_GUIDE})",
        "ldaps": f"secure LDAP on 636 and StartTLS with an uploaded PFX certificate ({_GUIDE}: LDAPS)",
        "schema-extension": f"LDIF schema extensions (domains.extendSchema): add, modify, rename ({_GUIDE}: schema "
                            "extension)",
        "password-policies": f"ten predefined fine-grained password policies, PSO-10 to PSO-100, set with AD tools "
                             f"({_GUIDE}: fine-grained password policies)",
        "multi-region": f"a domain in up to four regions ({_GUIDE}: quotas)",
        **{f"trust:forest:{direction}": _FOREST for direction in ("one-way-incoming", "one-way-outgoing", "two-way")}},
    unsupported={},
    partition_unsupported={},
    conditions={"ldaps": "a PFX certificate covering the domain and its wildcard, uploaded by hand"},
    notes={"*": (
        ("reserved range", f"The domain takes a /24 (or larger) range of its own, a /26 of it per region ({_GUIDE}: "
                           "domain API).", "Keep the reserved range (ciamCidr) out of every network's address plan."),
        ("delegated administration", f"Domain and Enterprise Admins are Google's; the customer administers the Cloud "
                                     f"OU ({_GUIDE}: delegated administrator).",
         "Create the platform's accounts and groups in OU=Cloud."))},
    users=f"Google documents moving users with their passwords only from another Active Directory, by a trust with "
          f"ADMT and the Password Export Server (domain migration, in Preview; {_GUIDE}); from an LDAP directory the "
          "passwords don't move: users set new ones, or the platform moves them as they sign in. Plan how users move, "
          "and record it.",
    limits={"password-policies": (10, f"ten predefined password policies ({_GUIDE})"),
            "regions": (4, f"four regions per domain ({_GUIDE}: quotas)")},
    editions={},
    default_base=lambda b: f"OU=Cloud,{domain_dn(one(b, 'ciamFqdn'))}" if one(b, "ciamFqdn") else None)
MANAGED = (GOOGLE_MANAGED_AD,)


# ------------------------------------------------------------------ render
def managed_ad_bindings(m):
    """Environment m's Managed Microsoft AD bindings."""
    return tuple(b for b in of_class(m, "ciamManagedDirectory") if one(b, "ciamManagedService") == SERVICE)


def _targets(m):
    return tuple(b for b in managed_ad_bindings(m) if is_target(b) and realizes_directory(b))


def _domain(m, b):
    regions = [x for x in (one(b, "ciamRegion"), *values(b, "ciamReplicaRegion")) if x]
    return tf_block("resource", ["google_active_directory_domain", tf_name(rdn_value(b))], [
        ("domain_name", recorded(b, "ciamFqdn", "domain")),
        ("locations", regions or [ref("var.region")]),
        ("reserved_ip_range", recorded(b, "ciamCidr", "reserved-range")),
        ("authorized_networks", [ref("data.google_compute_network.main.id")]),
        ("deletion_protection", True),
        ("labels", binding_labels(b, realizes=label(one(b, "ciamRealizes"))))])


def _target(m, b):
    return (*(comment(note_comment(x)) for x in _notes(m, b)), _domain(m, b))


def render_managed_ad(m):
    """HCL for environment m's Managed Microsoft AD domains holding the platform's user directory, each stamped with
    its entry (the render places it by its keeper), and a neighbour's note as its comment."""
    return (*(x for b in _targets(m) for x in from_entry(b.dn, _target(m, b))),
            *(comment(note_comment(_neighbour_note(m, b))) for b in managed_ad_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ notes
def _notes(m, b):
    """The render notes of a target: what isn't rendered."""
    label_, d = rdn_value(b), m.d
    own, policies = custom_schema(d), password_policies(d)
    return (
        *(note(AREA, "action", f"domain {label_} trust {rdn_value(t)}",
               f"{trust_summary(d, t)}: its handshake secret is shared with the other forest and would be in "
               "Terraform state, so the trust isn't rendered",
               ("Create it on both sides by hand (gcloud active-directory domains trusts create, and the other "
                "forest's administrators), then record its state",), b.dn, m.label) for t in trusts(d, b)),
        *((note(AREA, "action", f"domain {label_} LDAPS",
                "secure LDAP needs a PFX certificate for the domain, uploaded by hand: its private key and password "
                "stay out of Terraform state",
                ("Upload it with gcloud active-directory domains update-ldaps-settings",), b.dn, m.label),)
          if one(b, "ciamLdapsMode") in ("private", "internet") else ()),
        *((note(AREA, "action", f"domain {label_} schema",
                f"the record's own attribute types and object classes ({len(own)}) aren't in Active Directory's "
                "schema", ("Write them as an LDIF of attributeSchema and classSchema entries under their OIDs and "
                           "apply it with gcloud active-directory domains extend-schema",), b.dn, m.label),)
          if own else ()),
        *((note(AREA, "action", f"domain {label_} password policies",
                f"the record's password policies ({', '.join(rdn_value(p) for p in policies)}) map onto the "
                "predefined PSO-10 to PSO-100", ("Set their settings with AD tools and apply each to the groups of "
                                                 "its population",), b.dn, m.label),)
          if len(policies) > 1 or any(one(p, "ciamPopulation") for p in policies) else ()))


def _neighbour_note(m, b):
    keeper = get(m.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    return note(AREA, "note", f"domain {rdn_value(b)}",
                f"a neighbour directory the platform binds to, kept by {rdn_value(keeper) if keeper else 'its owner'}: "
                "not rendered", (f"Record changes its owner makes to it {RECORD}",), b.dn, m.label)


def managed_ad_notes(m):
    """The render notes of environment m's Managed Microsoft AD domains: each target's, and a neighbour's."""
    return (*chain.from_iterable(_notes(m, b) for b in _targets(m)),
            *(_neighbour_note(m, b) for b in managed_ad_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ read back
def managed_ad_resources(pairs):
    """Managed directory resources of (Terraform type, attributes) pairs: one per google_active_directory_domain, by
    its resource name: its domain, its first region and further ones, its reserved range, the role and realized role
    its labels name. A trust's handshake secret is never read."""
    def labelled(a):
        return label_tags(a.get("labels") or {})
    return tuple(resource("managed-directory", a.get("id") or a.get("name"), {
        "ciamManagedService": SERVICE, "ciamRealizes": labelled(a).get("Realizes"), "ciamFqdn": a.get("domain_name"),
        "ciamRegion": (a.get("locations") or [None])[0], "ciamReplicaRegion": tuple((a.get("locations") or [])[1:]),
        "ciamCidr": a.get("reserved_ip_range")},
        name=a.get("domain_name"), role=tagged_role(labelled(a)), tags=labelled(a))
        for a in of_types(pairs, "google_active_directory_domain") if a.get("id") or a.get("name"))
