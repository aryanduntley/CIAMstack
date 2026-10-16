"""Microsoft Entra Domain Services as a cloud-managed directory service (core directory domain: ciamManagedDirectory,
flow 76): what the planner knows of it (the ManagedDirectory descriptor, from Microsoft's documentation, research note
3196, read 2026-10-16), its Terraform render and its read back. Pure.

A target binding (ciamManagedService entra-domain-services, ciamRealizes ds) is rendered, each block stamped with its
entry:

  azurerm_active_directory_domain_service   the managed domain (its domain, SKU from the edition, its region, the
                                            subnet its first subnet role names), notifications to the DC and global
                                            administrators, hardened security (no NTLMv1, no TLS 1.0, no RC4;
                                            Kerberos and NTLM password hashes synchronized, NTLM's for LDAP simple
                                            binds; on-premises hashes when the cloud syncs password hashes), secure
                                            LDAP left out and ignored (lifecycle ignore_changes): its PFX and the PFX's
                                            password are in no Terraform state and no record (decision 3197)
  azurerm_active_directory_domain_service_replica_set   one per further region (ciamReplicaRegion), on a subnet given as
                                            a variable (a peered virtual network the environment doesn't bind)

The tenant's Domain Controller Services service principal, the virtual network's DNS servers, secure LDAP's
certificate, trusts (a password shared with the other forest), custom password policies and the OU the platform writes
in are actions. A neighbour (ciamPartnerOf) isn't the platform's to render: a note. An ARM render keeps both types in
Terraform (arm_types.KEPT): ARM declares replica sets as the managed domain's replicaSets property. Read back from
Terraform state: the managed domain's ID, domain, SKU, region and its replica sets' regions.
"""
from itertools import chain

from opsdir.core.contract import ManagedDirectory
from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import of_class, recorded
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.directory.managed import is_target, password_policies, realizes_directory, trust_summary, trusts
from opsdir.domains.estate.hybrid import directory_sync
from opsdir.domains.network.stack import subnets
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .account import tagged
from .external_id import partition
from .identities import LOC, RG
from .network import binding_tags

SERVICE = "entra-domain-services"
AREA = "Directory"
EDITIONS = ("standard", "enterprise", "premium")
SERVICE_PRINCIPAL = "2565bd9d-da50-47d4-8b85-4c97f669dc36"   # Domain Controller Services (the published application)

# ------------------------------------------------------------------ what Microsoft documents (read 2026-10-16)
_FAQ = "Entra Domain Services FAQ (2026-10)"
_GOV = "Entra Domain Services feature availability in Azure Government (updated 2026-02-21)"
_FOREST = f"forest trusts, one-way incoming, one-way outgoing or two-way ({_FAQ})"
ENTRA_DOMAIN_SERVICES = ManagedDirectory(
    name=SERVICE, title="Microsoft Entra Domain Services", partition=partition,
    available={"public": "Entra Domain Services overview (2026-10)", "usgovernment": f"{_GOV}: available"},
    absent={},
    supported={
        "ldap": "a managed Active Directory domain (Entra Domain Services overview, 2026-10)",
        "ldaps": "secure LDAP with an uploaded PFX certificate for the managed domain (secure LDAP tutorial, 2026-10)",
        "ldaps-internet": "secure LDAP over the internet on port 636, restricted by network security group rules "
                          "(secure LDAP tutorial, 2026-10)",
        "password-policies": "custom fine-grained password policies; the built-in policy can't be edited (password "
                             "and account lockout policies, 2026-10)",
        "multi-region": "replica sets in peered virtual networks of other regions (replica sets, 2026-10)",
        **{f"trust:forest:{direction}": _FOREST for direction in ("one-way-incoming", "one-way-outgoing", "two-way")}},
    unsupported={
        "schema-extension": f"Schema extensions aren't supported: Microsoft administers the managed domain's schema "
                            f"({_FAQ})",
        **{f"trust:external:{direction}": f"only forest trusts, no external domain trusts ({_FAQ})"
           for direction in ("one-way-incoming", "one-way-outgoing", "two-way")}},
    partition_unsupported={},
    conditions={"ldaps": "a PFX certificate covering the managed domain (a wildcard), uploaded to it by hand"},
    notes={"*": (
        ("service principal", f"The tenant needs the Domain Controller Services service principal (application "
                              f"{SERVICE_PRINCIPAL}) and an AAD DC Administrators group before the managed domain is "
                              "created (create a managed domain, 2026-10).",
         "Have the tenant's administrators register them once."),
        ("DNS", "The virtual network's DNS servers must be the managed domain's domain controllers.",
         "Set the virtual network's DNS servers to its controllers' addresses once it is created."),
        ("RC4", "Kerberos RC4 is disabled on managed domains from the week of 2026-07-13 (RC4 deprecation, 2026).",
         "Make every client use AES Kerberos."),
        ("LDAP simple binds", "LDAP simple binds need NTLM password hash synchronization (secure your domain, "
                              "2026-10).", "Keep it on while any consumer binds with a password.")),
        "usgovernment": (
            ("regions", "Microsoft's pages evidence the service in US Gov Virginia and US Gov Arizona; US Gov Texas "
                        "isn't established (2026-10).",
             "Confirm the region with Microsoft before placing it in US Gov Texas."),)},
    users="Users and their passwords come from the Entra tenant: users synchronized from Entra ID (from an on-premises "
          "directory through Entra Connect password hash synchronization) can't be created or changed in the managed "
          "domain, and a cloud user must change their password once before Entra ID holds the hashes it needs; "
          "accounts created in a custom OU stay local to the managed domain. Nothing imports passwords "
          f"(synchronization, {_FAQ}). Plan how users move, and record it.",
    limits={"regions": (5, "five replica sets, the first included (replica sets, 2026-10)")},
    editions={"multi-region": (("enterprise", "premium"), "Standard has no replica sets (pricing, 2026-10)"),
              "trust": (("enterprise", "premium"), "Standard has no trusts (pricing, 2026-10)")},
    default_base=lambda b: None,
    partition_unestablished={"usgovernment": {
        f"trust:forest:{direction}": f"{_GOV} lists creating trusts without their directions, and Microsoft's pages "
                                     "describe incoming and two-way trusts as newer"
        for direction in ("one-way-incoming", "two-way")}})
MANAGED = (ENTRA_DOMAIN_SERVICES,)
SKUS = {"standard": "Standard", "enterprise": "Enterprise", "premium": "Premium"}


# ------------------------------------------------------------------ render
def domain_service_bindings(m):
    """Environment m's Entra Domain Services bindings."""
    return tuple(b for b in of_class(m, "ciamManagedDirectory") if one(b, "ciamManagedService") == SERVICE)


def _targets(m):
    return tuple(b for b in domain_service_bindings(m) if is_target(b) and realizes_directory(b))


def _subnet_variable(n, region):
    return f"{n}_{tf_name(region)}_subnet_id"


def _domain(m, b, n):
    nets = subnets(m, b)
    sku = SKUS.get(one(b, "ciamDirectoryEdition")) or recorded(b, "ciamDirectoryEdition", "edition")
    region = one(b, "ciamRegion")
    return tf_block("resource", ["azurerm_active_directory_domain_service", n], [
        ("name", rdn_value(b)), ("location", region or LOC), ("resource_group_name", RG),
        ("domain_name", recorded(b, "ciamFqdn", "domain")), ("sku", sku),
        ("initial_replica_set", Block((
            ("subnet_id", ref(f"data.azurerm_subnet.{tf_name(rdn_value(nets[0]))}.id") if nets
             else recorded(b, "ciamSubnetRole", "subnet")),))),
        ("notifications", Block((("notify_dc_admins", True), ("notify_global_admins", True)))),
        ("security", Block((("ntlm_v1_enabled", False), ("tls_v1_enabled", False),
                            ("kerberos_rc4_encryption_enabled", False), ("sync_kerberos_passwords", True),
                            ("sync_ntlm_passwords", True),
                            ("sync_on_prem_passwords", "password-hash" in directory_sync(m))))),
        ("tags", tagged(m, {**binding_tags(b), "Realizes": one(b, "ciamRealizes")})),
        ("#", "secure LDAP is set by hand (its PFX and password stay out of Terraform state): ignored here"),
        ("lifecycle", Block((("ignore_changes", [ref("secure_ldap")]),)))])


def _replica_sets(m, b, n):
    return tuple(chain.from_iterable((
        tf_block("variable", [_subnet_variable(n, region)], [
            ("type", ref("string")),
            ("description", f"The subnet of managed domain {rdn_value(b)}'s replica set in {region} (a virtual network "
                            "peered with its own)")]),
        tf_block("resource", ["azurerm_active_directory_domain_service_replica_set", f"{n}_{tf_name(region)}"], [
            ("domain_service_id", ref(f"azurerm_active_directory_domain_service.{n}.id")), ("location", region),
            ("subnet_id", ref(f"var.{_subnet_variable(n, region)}"))]))
        for region in values(b, "ciamReplicaRegion")))


def _target(m, b):
    n = tf_name(rdn_value(b))
    return (*(comment(note_comment(x)) for x in _notes(m, b)), _domain(m, b, n), *_replica_sets(m, b, n))


def render_domain_services(m):
    """HCL for environment m's Entra Domain Services managed domains holding the platform's user directory, each
    stamped with its entry (the render places it by its keeper), and a neighbour's note as its comment."""
    return (*(x for b in _targets(m) for x in from_entry(b.dn, _target(m, b))),
            *(comment(note_comment(_neighbour_note(m, b))) for b in domain_service_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ notes
def _notes(m, b):
    """The render notes of a target: what is set by hand, and what isn't rendered."""
    label, d = rdn_value(b), m.d
    policies, regions = password_policies(d), values(b, "ciamReplicaRegion")
    return (
        note(AREA, "action", f"managed domain {label} prerequisites",
             f"the tenant's Domain Controller Services service principal ({SERVICE_PRINCIPAL}) and AAD DC "
             "Administrators group exist before it is created, and the virtual network's DNS servers point at its "
             "domain controllers after", ("Register the service principal and group once (the tenant's "
                                          "administrators), then set the virtual network's DNS servers",),
             b.dn, m.label),
        *((note(AREA, "action", f"managed domain {label} secure LDAP",
                "secure LDAP needs a PFX certificate for the managed domain, uploaded by hand: its private key and "
                "password stay out of Terraform state", ("Upload it (az or the portal) with external access as "
                                                         "ciamLdapsMode says, and allow 636 on the subnet's network "
                                                         "security group only from the consumers",), b.dn, m.label),)
          if one(b, "ciamLdapsMode") in ("private", "internet") else ()),
        *(note(AREA, "action", f"managed domain {label} trust {rdn_value(t)}",
               f"{trust_summary(d, t)}: its password is shared with the other forest and never in the record or "
               "Terraform state, so the trust isn't rendered",
               ("Create it on both sides by hand (the portal or az, and the other forest's administrators), then "
                "record its state",), b.dn, m.label) for t in trusts(d, b)),
        *((note(AREA, "action", f"managed domain {label} password policies",
                f"the record's password policies ({', '.join(rdn_value(p) for p in policies)}) are custom "
                "fine-grained password policies there", ("Create them in the System Password Settings Container with "
                                                         "AD tools and apply each to its population's group",),
                b.dn, m.label),) if len(policies) > 1 or any(one(p, "ciamPopulation") for p in policies) else ()),
        *((note(AREA, "action", f"managed domain {label} OU",
                "the platform's entries go in a custom OU an AAD DC Administrator creates",
                ("Create it, record it (ciamWritableBase)",), b.dn, m.label),) if not one(b, "ciamWritableBase")
          else ()),
        *((note(AREA, "action", f"managed domain {label} replica sets",
                "each replica set's subnet is in a peered virtual network this environment doesn't bind",
                (f"Give {', '.join(f'var.{_subnet_variable(tf_name(label), r)}' for r in regions)} when applying",),
                b.dn, m.label),) if regions else ()))


def _neighbour_note(m, b):
    keeper = get(m.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    return note(AREA, "note", f"managed domain {rdn_value(b)}",
                f"a neighbour directory the platform binds to, kept by {rdn_value(keeper) if keeper else 'its owner'}: "
                "not rendered", (f"Record changes its owner makes to it {RECORD}",), b.dn, m.label)


def domain_service_notes(m):
    """The render notes of environment m's Entra Domain Services managed domains: each target's, and a neighbour's."""
    return (*chain.from_iterable(_notes(m, b) for b in _targets(m)),
            *(_neighbour_note(m, b) for b in domain_service_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ read back
def domain_service_resources(pairs):
    """Managed directory resources of (Terraform type, attributes) pairs: one per
    azurerm_active_directory_domain_service, by its ID: its domain, SKU, region, its replica sets' regions, the role
    and Realizes its tags name. Secure LDAP's certificate and password are never read."""
    replicas = {}
    for a in of_types(pairs, "azurerm_active_directory_domain_service_replica_set"):
        replicas.setdefault((a.get("domain_service_id") or "").lower(), []).append(a.get("location"))
    return tuple(resource("managed-directory", a.get("id"), {
        "ciamManagedService": SERVICE, "ciamRealizes": (a.get("tags") or {}).get("Realizes"),
        "ciamFqdn": a.get("domain_name"), "ciamDirectoryEdition": (a.get("sku") or "").lower() or None,
        "ciamRegion": a.get("location"), "ciamReplicaRegion": tuple(replicas.get((a.get("id") or "").lower(), ()))},
        name=a.get("name"), role=tagged_role(a.get("tags") or {}), tags=a.get("tags") or {})
        for a in of_types(pairs, "azurerm_active_directory_domain_service") if a.get("id"))
