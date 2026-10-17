"""AWS Managed Microsoft AD as a cloud-managed directory service (core directory domain: ciamManagedDirectory, flow
76): what the planner knows of it (the ManagedDirectory descriptor, from AWS's documentation, research note 3196, read
2026-10-16), its render and its read back. Pure.

A target binding (ciamManagedService aws-managed-ad, ciamRealizes ds) is rendered, each block stamped with its entry:

  aws_cloudformation_stack            the directory as a CloudFormation stack (AWS::DirectoryService::MicrosoftAD:
                                      its domain, NetBIOS name, edition, the VPC and the two subnets its subnet roles
                                      name; DeletionPolicy and UpdateReplacePolicy Retain), the Admin password a
                                      Secrets Manager dynamic reference to the credential role's secret
                                      ({{resolve:secretsmanager:<id>}}): CloudFormation resolves it when it creates
                                      the directory, so no password is in the template, the Terraform state or the
                                      record (AWS's dynamic references and the type's schema: Password is write-only;
                                      decision 3197). Outputs: the directory ID and its DNS addresses only.
  aws_directory_service_region        one per further region (ciamReplicaRegion), on that region's VPC and subnets
                                      given as variables (the environment binds its own region's network only)
  aws_directory_service_conditional_forwarder   one per trust recording its domain's DNS servers

Terraform's aws_directory_service_directory takes the password as a plain argument kept in its state, so it isn't
used. A CloudFormation render keeps all three in the Terraform root beside the template (cfn_types.NO_NATIVE): the
stack already is CloudFormation. Trusts (a password shared with the other domain), server-side LDAPS (a certificate
enrolled from a CA), schema extensions, the predefined password policies' settings and domain controllers beyond two
are actions. A neighbour (ciamPartnerOf) isn't the platform's to render: a note. Read back from the stack (the
CloudFormation importer, its MicrosoftAD normalized to aws_directory_service_directory), from Terraform state (the
stack's template and outputs) and from the CLI (cli_directory.py): the directory's ID, domain, NetBIOS name, edition,
regions and tags. The password is never read.
"""
import json
from itertools import chain

from opsdir.core.contract import ManagedDirectory
from opsdir.core.directory import get, one, rdn_value, values
from opsdir.core.environment import of_class
from opsdir.core.inventory import of_types, resource, tagged_role
from opsdir.core.notes import RECORD, note, note_comment
from opsdir.domains.directory.managed import (custom_schema, domain_dn, is_target, password_policies,
                                              realizes_directory, trust_summary, trusts)
from opsdir.domains.network.stack import subnets
from opsdir_format_terraform.hcl import Block, comment, from_entry, jsonencoded, ref, tf_block, tf_name
from .account import partition
from .network import binding_tags
from .tags import state_tags

SERVICE = "aws-managed-ad"
AREA = "Directory"
EDITIONS = ("standard", "enterprise")
STACK_EDITIONS = {"standard": "Standard", "enterprise": "Enterprise"}
MICROSOFT_AD = "AWS::DirectoryService::MicrosoftAD"
SECRET_SCHEME = "aws-sm://"
STACK_TIMEOUTS = (("create", "90m"), ("update", "90m"), ("delete", "60m"))   # creation takes 20 to 45 minutes

# ------------------------------------------------------------------ what AWS documents (read 2026-10-16)
_GUIDE = "AWS Directory Service Admin Guide (2026-10)"
_GOV = "AWS GovCloud (US) User Guide, AWS Directory Service (2026-10)"
_TRUSTS = f"forest and external trusts, incoming, outgoing or two-way, selective authentication optional ({_GUIDE}: " \
          "trusts)"
AWS_MANAGED_AD = ManagedDirectory(
    name=SERVICE, title="AWS Managed Microsoft AD", partition=partition,
    available={"aws": _GUIDE, "aws-us-gov": f"{_GOV}: GovCloud (US-West) and GovCloud (US-East)"},
    absent={},
    supported={
        "ldap": f"Microsoft Active Directory run by AWS ({_GUIDE})",
        "ldaps": f"server-side LDAPS ({_GUIDE}: server-side LDAPS)",
        "schema-extension": f"LDIF schema extensions (StartSchemaExtension): new attributes and classes under unique "
                            f"OIDs, additions to existing classes; nothing can be deleted ({_GUIDE}: schema "
                            "extensions)",
        "password-policies": f"five predefined fine-grained password policies, CustomerPSO-01 to -05, set with AD "
                             f"tools ({_GUIDE}: password policies)",
        "multi-region": f"multi-Region replication ({_GUIDE}: multi-Region replication)",
        **{f"trust:{kind}:{direction}": _TRUSTS for kind in ("forest", "external")
           for direction in ("one-way-incoming", "one-way-outgoing", "two-way")}},
    unsupported={},
    partition_unsupported={},
    conditions={"ldaps": "a certificate for its domain controllers enrolled from AWS Private CA (Connector for AD) or "
                         "a Microsoft Enterprise CA in the domain"},
    notes={"*": (
        ("DNS", "The VPC's resolvers must send the domain's names to its domain controllers (a DHCP options set or a "
                "Route 53 Resolver rule).", "Point the VPC's DNS at the directory before joining servers."),
        ("delegated administration", f"Its Admin account administers the customer OU only, not Domain Admins "
                                     f"({_GUIDE}: Admin account).",
         "Create the platform's service accounts and groups in the customer OU.")),
        "aws-us-gov": (
            ("GovCloud", f"Directory sharing with other accounts, Hybrid Edition and the Directory Service Data API "
                         f"are unavailable there, and automatic DNS forwarding is off ({_GOV}).",
             "Configure DNS forwarding yourself, and share nothing across accounts."),
            ("export control", f"Directory metadata (its DNS and NetBIOS names, alias, description, tags, schema "
                               f"extension descriptions) must not hold export-controlled data ({_GOV}).",
             "Review those values before the directory is created."))},
    users=f"AWS documents moving users with their passwords only from another Active Directory, with ADMT and the "
          f"Password Export Service ({_GUIDE}: migrate users); from an LDAP directory the passwords don't move: users "
          "set new ones, or the platform moves them as they sign in. Plan how users move, and record it.",
    limits={"password-policies": (5, f"five predefined password policies ({_GUIDE}: password policies)"),
            "regions": (5, f"five Regions per directory, its own included ({_GUIDE}: quotas)")},
    editions={"multi-region": (("enterprise",), f"multi-Region replication needs Enterprise Edition ({_GUIDE})")},
    default_base=lambda b: f"OU={netbios(b)},{domain_dn(one(b, 'ciamFqdn'))}" if one(b, "ciamFqdn") else None,
    partition_unestablished={"aws-us-gov": {
        "multi-region": f"{_GOV} doesn't list multi-Region replication among what GovCloud lacks, and AWS's "
                        "replication guide doesn't name GovCloud"}})
MANAGED = (AWS_MANAGED_AD,)


def netbios(b):
    """A managed directory's NetBIOS name: ciamNetbiosName, else the first label of its domain in capitals (AWS's
    default), at most 15 characters."""
    return (one(b, "ciamNetbiosName") or (one(b, "ciamFqdn") or "").split(".")[0].upper())[:15]


# ------------------------------------------------------------------ render
def directory_bindings(m):
    """Environment m's AWS Managed Microsoft AD bindings."""
    return tuple(b for b in of_class(m, "ciamManagedDirectory") if one(b, "ciamManagedService") == SERVICE)


def _targets(m):
    return tuple(b for b in directory_bindings(m) if is_target(b) and realizes_directory(b))


def password_reference(m, b):
    """The Secrets Manager dynamic reference to the Admin password (the credential role's aws-sm secret), or None."""
    role = one(b, "ciamCredentialRole")
    uri = next((one(s, "ciamRefUri") for s in m.bindings if role and one(s, "ciamBindingRole") == role), None) or ""
    return "{{resolve:secretsmanager:" + uri[len(SECRET_SCHEME):] + "}}" if uri.startswith(SECRET_SCHEME) else None


def _missing(m, b):
    """What a target records too little of to create its directory, in words (empty: nothing)."""
    return tuple(what for what, lacking in (
        ("its domain (ciamFqdn)", not one(b, "ciamFqdn")),
        ("its Admin password's Secrets Manager secret (ciamCredentialRole, an aws-sm reference)",
         password_reference(m, b) is None),
        ("two subnets in different zones (ciamSubnetRole)", len(subnets(m, b)) != 2)) if lacking)


def directory_template(m, b):
    """The CloudFormation template of a target's directory: the MicrosoftAD (retained when deleted or replaced), its
    VPC and subnets by the Terraform data sources, the password by its dynamic reference; outputs its ID and DNS
    addresses."""
    edition = STACK_EDITIONS.get(one(b, "ciamDirectoryEdition"))
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": f"AWS Managed Microsoft AD {rdn_value(b)} ({m.label}), rendered by opsdir: the Admin "
                           "password is a Secrets Manager dynamic reference CloudFormation resolves",
            "Resources": {"Directory": {
                "Type": MICROSOFT_AD, "DeletionPolicy": "Retain", "UpdateReplacePolicy": "Retain",
                "Properties": {"Name": one(b, "ciamFqdn"), "ShortName": netbios(b),
                               **({"Edition": edition} if edition else {}), "Password": password_reference(m, b),
                               "VpcSettings": {"VpcId": ref("data.aws_vpc.main.id"),
                                               "SubnetIds": [ref(f"data.aws_subnet.{tf_name(rdn_value(s))}.id")
                                                             for s in subnets(m, b)]}}}},
            "Outputs": {"DirectoryId": {"Value": {"Ref": "Directory"}},
                        "DnsIpAddresses": {"Value": {"Fn::Join": [",", {"Fn::GetAtt": ["Directory",
                                                                                       "DnsIpAddresses"]}]}}}}


def _directory_id(n):
    return ref(f'aws_cloudformation_stack.{n}.outputs["DirectoryId"]')


def _region_variables(n, region):
    return f"{n}_{tf_name(region)}_vpc_id", f"{n}_{tf_name(region)}_subnet_ids"


def _regions(m, b, n):
    count = one(b, "ciamReplicaCount")
    return tuple(chain.from_iterable((
        tf_block("variable", [vpc], [("type", ref("string")),
                                     ("description", f"The VPC of directory {rdn_value(b)} in {region}")]),
        tf_block("variable", [nets], [("type", ref("list(string)")),
                                      ("description", f"Two subnets of directory {rdn_value(b)} in {region}, in "
                                                      "different zones")]),
        tf_block("resource", ["aws_directory_service_region", f"{n}_{tf_name(region)}"], [
            ("directory_id", _directory_id(n)), ("region_name", region),
            *((("desired_number_of_domain_controllers", int(count)),) if count else ()),
            ("vpc_settings", Block((("vpc_id", ref(f"var.{vpc}")), ("subnet_ids", ref(f"var.{nets}"))))),
            ("tags", binding_tags(b))]))
        for region in values(b, "ciamReplicaRegion") for vpc, nets in (_region_variables(n, region),)))


def _forwarders(m, b, n):
    return tuple(tf_block("resource", ["aws_directory_service_conditional_forwarder", f"{n}_{tf_name(rdn_value(t))}"], [
        ("directory_id", _directory_id(n)), ("remote_domain_name", one(t, "ciamFqdn")),
        ("dns_ips", list(values(t, "ciamForwardTarget")))])
        for t in trusts(m.d, b) if values(t, "ciamForwardTarget"))


def _target(m, b):
    n, missing = tf_name(rdn_value(b)), _missing(m, b)
    notes = tuple(comment(note_comment(x)) for x in _notes(m, b))
    if missing:
        return (*notes, comment(f"UNBOUND: directory {rdn_value(b)} records no {'; no '.join(missing)}: not "
                                "rendered"))
    return (*notes, tf_block("resource", ["aws_cloudformation_stack", n], [
        ("name", f"ciam-{rdn_value(m.env)}-{rdn_value(b)}-directory"),
        ("template_body", jsonencoded(directory_template(m, b))),
        ("tags", {**binding_tags(b), "Realizes": one(b, "ciamRealizes")}),
        ("timeouts", Block(STACK_TIMEOUTS))]),
            *_regions(m, b, n), *_forwarders(m, b, n))


def render_directories(m):
    """HCL for environment m's AWS Managed Microsoft AD directories holding the platform's user directory, each stamped
    with its entry (the render places it by its keeper), and a neighbour's note as its comment."""
    return (*(x for b in _targets(m) for x in from_entry(b.dn, _target(m, b))),
            *(comment(note_comment(_neighbour_note(m, b))) for b in directory_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ notes
def _notes(m, b):
    """The render notes of a target: what isn't rendered, and how the Admin password is kept."""
    label, d = rdn_value(b), m.d
    own, policies, count = custom_schema(d), password_policies(d), one(b, "ciamReplicaCount")
    missing = _missing(m, b)
    given = tuple(v for r in values(b, "ciamReplicaRegion") for v in _region_variables(tf_name(label), r))
    return (
        *((note(AREA, "action", f"directory {label}", f"records no {'; no '.join(missing)}: the directory isn't "
                                                      "rendered", (f"Record them {RECORD}",), b.dn, m.label),)
          if missing else ()),
        *((note(AREA, "note", f"directory {label} Admin password",
                "CloudFormation resolves the Secrets Manager reference when it creates the directory: changing the "
                "secret later doesn't change the Admin password, and changing the reference replaces the directory",
                ("Reset the Admin password with aws ds reset-user-password, then store it in the secret",),
                b.dn, m.label),) if not missing else ()),
        *(note(AREA, "action", f"directory {label} trust {rdn_value(t)}",
               f"{trust_summary(d, t)}: its password is shared with the other domain and never in the record or "
               "Terraform state, so the trust isn't rendered",
               ("Create it on both sides by hand (aws ds create-trust, and the other domain's administrators), "
                "then record its state",), b.dn, m.label) for t in trusts(d, b)),
        *((note(AREA, "action", f"directory {label} LDAPS",
                "server-side LDAPS needs a certificate for its domain controllers, enrolled from a CA",
                ("Enrol it from AWS Private CA (Connector for AD) or an Enterprise CA, then run aws ds enable-ldaps "
                 "--type Server",), b.dn, m.label),)
          if one(b, "ciamLdapsMode") in ("private", "internet") else ()),
        *((note(AREA, "action", f"directory {label} schema",
                f"the record's own attribute types and object classes ({len(own)}) aren't in Active Directory's "
                "schema", ("Write them as an LDIF of attributeSchema and classSchema entries under their OIDs and "
                           "apply it with aws ds start-schema-extension",), b.dn, m.label),) if own else ()),
        *((note(AREA, "action", f"directory {label} password policies",
                f"the record's password policies ({', '.join(rdn_value(p) for p in policies)}) map onto the "
                "predefined CustomerPSO-01 to -05", ("Set their settings with AD tools and apply each to the groups "
                                                     "of its population",), b.dn, m.label),)
          if len(policies) > 1 or any(one(p, "ciamPopulation") for p in policies) else ()),
        *((note(AREA, "action", f"directory {label} domain controllers",
                f"CloudFormation creates two domain controllers; the record asks for {count}",
                (f"Run aws ds update-number-of-domain-controllers --desired-number {count}",), b.dn, m.label),)
          if count and int(count) > 2 else ()),
        *((note(AREA, "action", f"directory {label} regions",
                "each further region's VPC and subnets are another network than this environment's",
                (f"Give {', '.join(f'var.{v}' for v in given)} when applying",), b.dn, m.label),)
          if given and not missing else ()))


def _neighbour_note(m, b):
    keeper = get(m.d, one(b, "ciamManagedBy")) if one(b, "ciamManagedBy") else None
    return note(AREA, "note", f"directory {rdn_value(b)}",
                f"a neighbour directory the platform binds to, kept by {rdn_value(keeper) if keeper else 'its owner'}: "
                "not rendered", (f"Record changes its owner makes to it {RECORD}",), b.dn, m.label)


def directory_notes(m):
    """The render notes of environment m's AWS Managed Microsoft AD directories: each target's, and a neighbour's."""
    return (*chain.from_iterable(_notes(m, b) for b in _targets(m)),
            *(_neighbour_note(m, b) for b in directory_bindings(m) if not is_target(b)))


# ------------------------------------------------------------------ read back
def _stacked(a):
    """The (Terraform type, attributes) pair of the directory an opsdir stack declares (aws_cloudformation_stack in
    state: its template's MicrosoftAD, the directory ID from its outputs), or None. Its Password isn't read."""
    try:
        template = json.loads(a.get("template_body") or "{}")
    except (TypeError, ValueError):
        return None
    found = next((r.get("Properties") or {} for r in (template.get("Resources") or {}).values()
                  if isinstance(r, dict) and r.get("Type") == MICROSOFT_AD), None)
    outputs = a.get("outputs") or {}
    if found is None or not outputs.get("DirectoryId"):
        return None
    return "aws_directory_service_directory", {"id": outputs["DirectoryId"], "name": found.get("Name"),
                                               "short_name": found.get("ShortName"), "edition": found.get("Edition"),
                                               "tags": a.get("tags") or {}}


def directory_resources(pairs):
    """Managed directory resources of (Terraform type, attributes) pairs: one per aws_directory_service_directory of
    type MicrosoftAD (state, the CloudFormation importer, the CLI) or opsdir directory stack, by its ID: its domain,
    NetBIOS name, edition, regions (its aws_directory_service_region entries, or the CLI's), the role and Realizes its
    tags name. No password is read."""
    stacked = tuple(p for p in (_stacked(a) for a in of_types(pairs, "aws_cloudformation_stack")) if p)
    regions = {}
    for a in of_types(pairs, "aws_directory_service_region"):
        regions.setdefault(a.get("directory_id"), []).append(a.get("region_name"))
    found = (*(a for t, a in stacked), *(a for a in of_types(pairs, "aws_directory_service_directory")
                                         if (a.get("type") or "MicrosoftAD") == "MicrosoftAD"))
    return tuple(resource("managed-directory", a.get("id"), {
        "ciamManagedService": SERVICE, "ciamRealizes": state_tags(a).get("Realizes"), "ciamFqdn": a.get("name"),
        "ciamNetbiosName": a.get("short_name"), "ciamDirectoryEdition": (a.get("edition") or "").lower() or None,
        "ciamReplicaRegion": tuple(a.get("additional_regions") or regions.get(a.get("id"), ()))},
        name=state_tags(a).get("Name") or a.get("name"), role=tagged_role(state_tags(a)), tags=state_tags(a))
        for a in {x.get("id"): x for x in found if x.get("id")}.values())
