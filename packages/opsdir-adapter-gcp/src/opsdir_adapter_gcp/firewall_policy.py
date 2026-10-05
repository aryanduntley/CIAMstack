"""Google Cloud's firewall policy model (an environment whose network's ciamFirewallModel is 'policy'): instead of VPC
firewall rules targeting network tags, a network firewall policy attached to the network, its rules targeting secure
tags. A tag key with purpose GCE_FIREWALL for the network (the record's, ciamTagKeyRef, else one rendered here), a value
per server role, bound to each instance in its zone (a key rendered here says it is opsdir's in its description, so the
importers don't take it for one the record must reference); the record's inbound rules, the health-check probe rules of
the service names and the egress allowlist become the policy's rules. The policy, its rules and the tag key live in the
network's project (a Shared VPC's host project); binding a tag value needs the Tag User role on it, an access request.
Which the network evaluates first, its VPC rules or the policy, is the network's setting (the landing zone's): said in a
comment. Hierarchical policies are read, never rendered. Pure."""
from opsdir.core.directory import one, rdn_value, values
from opsdir.core.environment import of_class, one_role
from opsdir.domains.infrastructure.firewall import rule_priorities, rule_purpose
from opsdir.domains.network.stack import allowlist, network_policy, owned, private_ranges
from opsdir_adapter_gcp.identities import project_of
from opsdir_adapter_gcp.names import name_parts
from opsdir_adapter_gcp.names import MANAGED, NETWORK
from opsdir_format_terraform.hcl import Block, block, ref, tf_name

POLICY = "network_policy"
TAG_KEY = "server_role"
# priorities above the record's rules (at most 65535): what a load balancer needs admitted (health-check probes, an
# application load balancer's proxies), then the egress allowlist, then the deny
ADMITS = {"health_checks": (70000, "Google Cloud health checks for"), "proxies": (75000, "Load balancer proxies for")}
EGRESS, DENY = 80000, 2147483000
ORDER = {"policy-first": "BEFORE_CLASSIC_FIREWALL", "rules-first": "AFTER_CLASSIC_FIREWALL"}


def _net_path(m):
    return name_parts(one(one_role(m, "network"), "ciamProviderRef"))


def network_project(m):
    """The project argument for what lives in the network's project, or none (the provider's project)."""
    return project_of(_net_path(m))


def roles(m):
    """The server roles environment m's instances carry, sorted."""
    return tuple(sorted({one(s, "ciamServerRole") for s in m.servers}))


def tag_value(role):
    """The tag value (tagValues/...) a role's instances are bound to."""
    return ref(f"google_tags_tag_value.{tf_name(role)}.id")


def _policy_name(m):
    p = network_policy(m)
    return f"ciam-{rdn_value(m.env)}" + (f"-{rdn_value(p)}" if p is not None else "")


def policy_ref(m):
    """What the policy's rules name as their policy: the rendered policy's name, or the provider ref of the network
    policy someone else keeps."""
    p = network_policy(m)
    return one(p, "ciamProviderRef") if p is not None and not owned(p) else ref(
        f"google_compute_network_firewall_policy.{POLICY}.name")


def _tag_key(m):
    """(blocks, the tag key id) of the tag key the policy targets servers by: the record's, else one rendered here."""
    p, path = network_policy(m), _net_path(m)
    key = one(p, "ciamTagKeyRef") if p is not None else None
    if key:
        return (), key
    project = path.get("projects")
    network = f"{project}/{path['networks']}" if project and "networks" in path else None
    return ((block("resource", ["google_tags_tag_key", TAG_KEY], [
        ("parent", f"projects/{project}" if project else ref('"projects/${var.project_id}"')),
        ("short_name", f"ciam-{rdn_value(m.env)}-role"),
        ("description", f"CIAM server role ({m.label}): what the firewall policy's rules target. {MANAGED}"),
        ("purpose", "GCE_FIREWALL"),
        ("purpose_data", {"network": network or ref('"${var.project_id}/' + path.get("networks", "") + '"')})]),),
        ref(f"google_tags_tag_key.{TAG_KEY}.id"))


def _binding(s):
    n, zone = tf_name(rdn_value(s)), one(s, "ciamZone")
    return block("resource", ["google_tags_location_tag_binding", n], [
        ("parent", ref(f'"//compute.googleapis.com/projects/${{var.project_id}}/zones/{zone}/instances/'
                       f'${{google_compute_instance.{n}.instance_id}}"')),
        ("tag_value", tag_value(one(s, "ciamServerRole"))), ("location", zone)])


def _rule(m, n, prio, direction, action, match, targets, description, name=None, policy=None):
    return block("resource", ["google_compute_network_firewall_policy_rule", n], [
        ("firewall_policy", policy or policy_ref(m)), *network_project(m), ("priority", prio), ("direction", direction),
        ("action", action), *((("rule_name", name),) if name else ()), ("description", description),
        ("match", Block(match)), *(("target_secure_tags", Block((("name", t),))) for t in targets)])


def _layer4(protocol, ports=()):
    return ("layer4_configs", Block((("ip_protocol", protocol), *((("ports", [str(p) for p in ports]),) if ports
                                                                    else ()))))


def _hierarchical(m, fw):
    """The hierarchical policy a rule says it belongs to, when it does (read, never rendered)."""
    p = one_role(m, one(fw, "ciamPolicyRole")) if one(fw, "ciamPolicyRole") else None
    return p if p is not None and one(p, "ciamPolicyScope") == "hierarchical" else None


def ingress_rules(m):
    """The record's inbound rules as the policy's rules (priorities pinned like the VPC rules'), targeting the role's
    tag value; a comment for a rule a hierarchical policy holds."""
    rules = of_class(m, "ciamFirewallRule")
    prios = rule_priorities(rules, 1000, 10, 65535)
    out = []
    for fw in rules:
        prio, pinned = prios[fw.dn]
        held = _hierarchical(m, fw)
        if held is not None:
            out.append(f"# {rdn_value(fw)} belongs to the hierarchical policy '{rdn_value(held)}' (read, not rendered)")
            continue
        out += [f"# NOTE: {rdn_value(fw)} has no pinned ciamRulePriority; assigned {prio}. Pin it in the directory."] \
            if not pinned else []
        out.append(_rule(m, tf_name(rdn_value(fw)), prio, "INGRESS", "allow", (
            ("src_ip_ranges", values(fw, "ciamSourceCidr")),
            _layer4(one(fw, "ciamProtocol", "tcp"), values(fw, "ciamPort"))),
            (tag_value(one(fw, "ciamTargetRole")),), rule_purpose(m, fw), rdn_value(fw)))
    return tuple(out)


def health_check_rule(m, svc, n, ranges, port, kind="health_checks"):
    """The policy rule admitting what a service's load balancer needs to its servers on its port: Google Cloud's
    health-check probes, or (kind proxies) an application load balancer's proxies."""
    services = of_class(m, "ciamServiceName")
    base, what = ADMITS[kind]
    prio = base + next(i for i, s in enumerate(services) if s.dn == svc.dn)
    return _rule(m, f"{n}_{kind}", prio, "INGRESS", "allow", (
        ("src_ip_ranges", list(ranges)), _layer4("tcp", (port,))), (tag_value(one(svc, "ciamTargetRole")),),
        f"{what} {rdn_value(svc)}")


def egress_rules(m, proxy, targets=None, policy=None):
    """An egress firewall's allowlist as the policy's egress rules for every role's tag value (or the targets given;
    none: every instance of the network) in the environment's policy (or the policy given): the sites by name
    (wildcard domains can't be FQDN objects: said), the ranges the stack reaches privately, then everything else
    denied."""
    targets = tuple(tag_value(r) for r in roles(m)) if targets is None else targets
    n = tf_name(rdn_value(proxy))
    sites = tuple((port, tuple(h for h in hosts if not h.startswith("*.")),
                   tuple(h for h in hosts if h.startswith("*."))) for port, hosts in allowlist(proxy))
    private = private_ranges(m)
    return (*(f"# {h}: a wildcard domain can't be an FQDN object; allow its hosts by name" for _, _, w in sites
              for h in w),
            *(_rule(m, f"{n}_sites_{port}", EGRESS + i, "EGRESS", "allow", (
                ("dest_fqdns", list(named)), _layer4("tcp", (port,))), targets,
                f"Sites the CIAM platform reaches on {port} ({rdn_value(proxy)})", policy=policy)
              for i, (port, named, _) in enumerate(sites) if named),
            *((_rule(m, f"{n}_private", EGRESS + len(sites), "EGRESS", "allow", (
                ("dest_ip_ranges", list(private)), _layer4("all")), targets,
                "What the CIAM platform reaches privately (its network, interconnects, private endpoints)",
                policy=policy),)
              if private else ()),
            _rule(m, f"{n}_deny", DENY, "EGRESS", "deny", (("dest_ip_ranges", ["0.0.0.0/0"]), _layer4("all")),
                  targets, f"Other egress to the internet ({rdn_value(proxy)} allows only its sites)", policy=policy))


def policy_firewall(m):
    """The policy model's blocks: the policy and its association (unless someone else keeps the network policy), the
    tag key and a value per role, each instance's tag binding, the record's inbound rules."""
    p, path = network_policy(m), _net_path(m)
    blocks, key = _tag_key(m)
    order = one(p, "ciamPolicyOrder") if p is not None else None
    notes = (*((f"# The network evaluates {'its policy' if order == 'policy-first' else 'its VPC rules'} first: "
                f"network_firewall_policy_enforcement_order = {ORDER[order]} on its network (the landing zone "
                "keeps it)",) if order else ()),
             *((f"# The network's project is {path['projects']}: the policy, its rules and the tag key live there, so "
                "the deployer needs rights in it",) if "projects" in path else ()),
             "# Binding the tag values to the instances needs roles/resourcemanager.tagUser on them for the deployer "
             "(an access request)")
    kept = p is not None and not owned(p)
    return (*notes,
            *(() if kept else (
                block("resource", ["google_compute_network_firewall_policy", POLICY], [
                    ("name", _policy_name(m)), *network_project(m),
                    ("description", f"CIAM firewall policy ({m.label}): rules target the servers' secure tags")]),
                block("resource", ["google_compute_network_firewall_policy_association", POLICY], [
                    ("name", _policy_name(m)), *network_project(m), ("attachment_target", NETWORK),
                    ("firewall_policy", ref(f"google_compute_network_firewall_policy.{POLICY}.id"))]))),
            *blocks,
            *(block("resource", ["google_tags_tag_value", tf_name(r)], [
                ("parent", key), ("short_name", r), ("description", f"CIAM {r} servers ({m.label})")])
              for r in roles(m)),
            *(_binding(s) for s in m.servers),
            *ingress_rules(m))
