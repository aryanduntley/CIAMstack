"""What the clouds report the environments run (pure: builds text). Generated from the same fixture data as the record,
so each export matches it except for the drift planted here, which `opsdir import --dry-run` shows:

  Every environment's public names are on the corporate DNS team's Infoblox, so neither Route 53 nor Azure DNS holds
  them (the load balancers' Service tags name them); the source's gateway load balancer sticks by source address, and
  the source forwards the AD domain by a Resolver rule.
  source/prod, AWS Terraform state (terraform.tfstate):
    - pf-engine-2 resized in the console (m6i.large -> m6i.xlarge)
    - an untagged bastion instance nobody recorded
    - a hand-opened security group rule, "temporary vendor access", 10.99.0.0/16 to LDAPS
    - the disk key's automatic rotation switched off
    - a CloudWatch alarm someone added in the console (ds-cpu-high), untagged: named, not recorded
    - PingFederate's role given secretsmanager:ListSecrets on everything in the console
  source/prod, the landing zone's Terraform state (landing-zone.tfstate): the pipeline's OIDC role, the admins'
    permission set, the break-glass role, whose AWS managed policy (AdministratorAccess) a state doesn't hold: named
  target/prod, Azure CLI output (az … -o json), with a role map:
    - fw-idm-sync's NSG priority changed in the portal (130 -> 400)
    - ds-3 resized (Standard_D4s_v5 -> Standard_D8s_v5)
    - a management subnet added in the portal, snet-mgmt; roles.json gives it the role subnet-mgmt
  standby/prod, Cloud Asset Inventory (an export, JSON lines) and gcloud output (--format=json):
    - ds-2 resized in the console (n2-standard-4 -> n2-standard-8; the instance list carries it)
    - an SSH rule for IAP opened by hand (35.235.240.0/20 to port 22): named, not recorded (no role)
    - Secret Manager names secrets by project number; `gcloud projects describe` reads them as the project ID
    - IAM as the inventory exports it (iam-policy, by project number), the service accounts and the pipeline's pool
      provider: as recorded, but for a service account nobody recorded (ciam-servers): counted
"""
import hashlib
import json
import re

from .access import ACCT, AWS_IDENTITIES, GCP_IDENTITIES, GITHUB, PRINCIPAL_ROWS
from .common import AWS, AZ, GCP
from .infrastructure import HOST, PROJECT, SECRET_ROLES, SOURCE, STANDBY, TARGET
from .observability import MONITORING

ACCOUNT, REGION = "111122223333", "us-east-1"
SUB = "00000000-0000-0000-0000-000000000000"
RG = f"/subscriptions/{SUB}/resourceGroups/rg-ciam-prod"
NET = f"{RG}/providers/Microsoft.Network"


def _hex(*parts, n=12):
    """A stable made-up hex ID for these parts (the same on every run)."""
    return hashlib.sha256("/".join(map(str, parts)).encode()).hexdigest()[:n]


def _dumps(doc):
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


# ------------------------------------------------------------------ source/prod: AWS Terraform state
def _res(mode, type_, name, attrs):
    return {"mode": mode, "type": type_, "name": name.replace("-", "_"),
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [{"schema_version": 1, "attributes": attrs, "sensitive_attributes": []}]}


def _source_ids(p):
    subnets = {cn: ref for cn, _, ref, _, _ in p["subnets"]}
    instances = {cn: f"i-0{_hex('instance', cn, n=16)}" for cn, *_ in p["servers"]}
    groups = {role: f"sg-0{_hex('group', role, n=16)}" for role in dict.fromkeys(s[1] for s in p["servers"])}
    return subnets, instances, groups


def _aws_network(p, subnets):
    return [_res("data", "aws_vpc", "main", {"id": p["net"][1], "cidr_block": p["net"][2]}),
            *(_res("data", "aws_subnet", cn, {"id": ref, "cidr_block": cidr, "availability_zone": zone,
                                              "vpc_id": p["net"][1]})
              for cn, _, ref, cidr, zone in p["subnets"]),
            _res("data", "aws_nat_gateway", "pf_egress", {"id": p["egress"][0], "public_ip": p["egress"][1][:-3]})]


def _aws_servers(p, subnets, instances, groups, resized):
    return [_res("managed", "aws_instance", cn, {
                "id": instances[cn], "ami": image, "instance_type": resized.get(cn, size), "private_ip": ip,
                "availability_zone": zone, "subnet_id": subnets[subnet], "vpc_security_group_ids": [groups[role]],
                "tags": {"Name": cn, "Role": role, "Hostname": host, "Product": version, "ManagedBy": "opsdir"}})
            for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]]


def _aws_firewall(p, groups):
    return [*(_res("managed", "aws_security_group", role, {"id": gid, "name": f"ciam-prod-{role}",
                                                           "vpc_id": p["net"][1], "ingress": []})
              for role, gid in groups.items()),
            *(_res("managed", "aws_vpc_security_group_ingress_rule", f"{cn}_{i}_{port}", {
                "security_group_rule_id": f"sgr-0{_hex(cn, cidr, port, n=16)}",
                "security_group_id": groups[trole], "cidr_ipv4": cidr, "from_port": port, "to_port": port,
                "ip_protocol": "tcp", "description": f"{consumer or role} ({cn})"})
              for cn, role, cidrs, ports, trole, consumer, _ in p["fw"] for i, cidr in enumerate(cidrs) for port in ports)]


def _aws_service(p, instances, cn, fqdn, zref, trole, ports, ip, pref):
    """A network load balancer, its Elastic IP (public) or private address, alias record, listeners and targets."""
    arn = f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:loadbalancer/net/ciam-prod-{cn}/{_hex(cn, n=16)}"
    dns = f"ciam-prod-{cn}-{_hex(cn, n=8)}.elb.{REGION}.amazonaws.com"
    internal = pref is None
    targets = [s[0] for s in p["servers"] if s[1] == trole]

    def group(port):
        return f"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/ciam-prod-{cn}-{port}/{_hex(cn, port, n=16)}"
    sticky = "stickiness source-ip" in (p.get("service_attrs") or {}).get(cn, {}).get("ciamEdgeFact", ())
    return [_res("managed", "aws_lb", cn, {"arn": arn, "name": f"ciam-prod-{cn}", "internal": internal,
                                           "load_balancer_type": "network", "dns_name": dns,
                                           "tags": {"Service": fqdn, "ManagedBy": "opsdir"}, "subnet_mapping": [
                                               {"private_ipv4_address": ip} if internal else {"allocation_id": pref}]}),
            *(() if internal else (_res("data", "aws_eip", cn, {"allocation_id": pref, "public_ip": ip}),)),
            # the public names are on the corporate DNS team's Infoblox: Route 53 holds the private one only
            *((_res("managed", "aws_route53_record", cn, {"name": fqdn, "zone_id": zref, "type": "A",
                                                          "alias": [{"name": dns, "zone_id": "Z26RNL4JYFTOTI"}]}),)
              if internal else ()),
            *(r for port in ports for r in (
                _res("managed", "aws_lb_target_group", f"{cn}_{port}", {
                    "arn": group(port), "port": port,
                    **({"stickiness": [{"type": "source_ip", "enabled": True}]} if sticky else {})}),
                _res("managed", "aws_lb_listener", f"{cn}_{port}", {
                    "load_balancer_arn": arn, "port": port,
                    "default_action": [{"type": "forward", "target_group_arn": group(port)}]}),
                *(_res("managed", "aws_lb_target_group_attachment", f"{cn}_{port}_{t}",
                       {"target_group_arn": group(port), "target_id": instances[t]}) for t in targets)))]


def _aws_services(p, instances):
    return [r for cn, _, fqdn, _, zref, trole, ports, ip, pref, _ in p["services"]
            for r in _aws_service(p, instances, cn, fqdn, zref, trole, ports, ip, pref)]


def _aws_keys(p, rotation):
    secret = p["secret"]
    rotated = {role: facts for role, facts in p["key_facts"].items() if facts.get("ciamRotationFunction")}
    key_arn = p["key"][0].split("://", 1)[1]
    return [*(_res("data", "aws_secretsmanager_secret", role, {"arn": secret(role).split("://", 1)[1],
                                                               "name": f"ciam/prod/{role}"})
              for role in SECRET_ROLES),
            *(_res("managed", "aws_secretsmanager_secret_rotation", role, {
                "secret_id": secret(role).split("://", 1)[1], "rotation_lambda_arn": facts["ciamRotationFunction"]})
              for role, facts in rotated.items()),
            _res("managed", "aws_kms_key", "disk", {"arn": key_arn, "key_id": key_arn.rsplit("/", 1)[1],
                                                    "enable_key_rotation": rotation}),
            *(_res("managed", "aws_kms_replica_key", f"disk_{r}", {"arn": key_arn.replace(REGION, r),
                                                                   "primary_key_arn": key_arn})
              for r in (p["key_facts"]["disk-encryption"].get("ciamReplicaRegion"),) if r),
            _res("data", "aws_s3_bucket", "ds_backups", {"bucket": p["backup"][len("s3://"):],
                                                         "arn": f"arn:aws:s3:::{p['backup'][len('s3://'):]}"}),
            *(_res("data", "aws_s3_bucket", "pf_cluster", {"bucket": bucket, "arn": f"arn:aws:s3:::{bucket}"})
              for bucket in (p["discovery"][len("s3://"):].split("/", 1)[0],) if p.get("discovery"))]


def _aws_monitoring():
    """CloudWatch as the source runs it: the alert topic, the log groups, the alarms and the canary the record holds
    (each tagged with its role or the rule it realizes), and one alarm nobody tagged (named in the dry run)."""
    by_class = {oc: [(cn, role, attrs) for c, cn, role, attrs in MONITORING["source"] if c == oc]
                for oc in ("ciamAlertChannel", "ciamLogDestination", "ciamAlarmBinding", "ciamCanaryBinding")}
    return [*(_res("managed", "aws_sns_topic", cn, {"arn": a["ciamProviderRef"], "name": f"ciam-prod-{cn}",
                                                    "tags": {"Role": role}})
              for cn, role, a in by_class["ciamAlertChannel"]),
            *(_res("managed", "aws_cloudwatch_log_group", cn, {
                "arn": a["ciamProviderRef"], "name": a["ciamProviderRef"].split("log-group:", 1)[1],
                "retention_in_days": a["ciamRetentionDays"], "tags": {"Role": role}})
              for cn, role, a in by_class["ciamLogDestination"]),
            *(_res("managed", "aws_cloudwatch_metric_alarm", cn, {
                "arn": a["ciamProviderRef"], "alarm_name": cn, "namespace": a["ciamMetric"].split(" ")[0],
                "metric_name": a["ciamMetric"].split(" ")[1], "alarm_actions": [a["ciamNotifies"]],
                "tags": {"Realizes": a["ciamRealizes"]}})
              for cn, _, a in by_class["ciamAlarmBinding"]),
            *(_res("managed", "aws_synthetics_canary", cn, {
                "arn": a["ciamProviderRef"], "name": f"ciam-{cn}", "schedule": [{"expression": "rate(5 minutes)"}],
                "tags": {"Realizes": a["ciamRealizes"]}})
              for cn, _, a in by_class["ciamCanaryBinding"]),
            _res("managed", "aws_cloudwatch_metric_alarm", "ds-cpu-high", {      # someone added it in the console
                "arn": "arn:aws:cloudwatch:us-east-1:111122223333:alarm:ds-cpu-high", "alarm_name": "ds-cpu-high",
                "namespace": "AWS/EC2", "metric_name": "CPUUtilization"})]


def _drifted_source(p, subnets, groups):
    """What someone did outside the record: an untagged bastion and a hand-opened rule."""
    return [_res("managed", "aws_instance", "bastion", {
                "id": "i-0b4571011cafe0001", "ami": "ami-0bastion0000000001", "instance_type": "t3.micro",
                "private_ip": "10.20.4.99", "availability_zone": "us-east-1a", "subnet_id": subnets["subnet-pf-a"],
                "vpc_security_group_ids": [groups["pf-engine"]], "private_dns": "ip-10-20-4-99.ec2.internal"}),
            _res("managed", "aws_vpc_security_group_ingress_rule", "vendor", {
                "security_group_rule_id": "sgr-0feedc0ffee000001", "security_group_id": groups["ds"],
                "cidr_ipv4": "10.99.0.0/16", "from_port": 1636, "to_port": 1636, "ip_protocol": "tcp",
                "description": "temporary vendor access"})]


# ------------------------------------------------------------------ source/prod: IAM, the platform's and the landing zone's
LANDING = ("identity-ci", "identity-admins", "identity-break-glass")      # kept by the landing zone, not the platform


def _policy(*statements):
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _allows(grants):
    """A policy's statements from the record's grants ('<action> on <resource>')."""
    return [{"Effect": "Allow", "Action": a, "Resource": r} for a, _, r in (g.partition(" on ") for g in grants)]


def _trust(trusted):
    def one(who):
        if who.startswith("https://"):
            issuer, subject = who.split(" ", 1)
            host = issuer.split("://", 1)[1]
            return {"Effect": "Allow", "Action": "sts:AssumeRoleWithWebIdentity",
                    "Principal": {"Federated": f"{ACCT}:oidc-provider/{host}"},
                    "Condition": {"StringEquals": {f"{host}:aud": "sts.amazonaws.com"},
                                  "StringLike": {f"{host}:sub": subject}}}
        if who.endswith(".amazonaws.com"):
            return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"Service": who}}
        return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": who},
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}
    return _policy(*(one(w) for w in trusted))


def _role(cn, ref, trusted, grants, extra=(), managed=()):
    name = ref.rsplit("/", 1)[1]
    return _res("managed", "aws_iam_role", name, {
        "arn": ref, "name": name, "assume_role_policy": _trust(trusted), "tags": {"Role": cn},
        "inline_policy": [{"name": "ciam", "policy": _policy(*_allows(grants), *extra)}] if grants or extra else [],
        "managed_policy_arns": list(managed)})


def _source_iam():
    """The platform's workload roles, PingFederate's with the grant someone added in the console."""
    console = ({"Effect": "Allow", "Action": "secretsmanager:ListSecrets", "Resource": "*"},)
    return [_role(cn, ref, trusted, grants, console if cn == "identity-pf" else ())
            for cn, kind, ref, trusted, grants in AWS_IDENTITIES if cn not in LANDING]


def landing_zone_state():
    """The landing zone's Terraform state: the pipeline's OIDC provider and role, the admins' permission set, the
    break-glass role (its AWS managed policy isn't in a state)."""
    rows = {cn: (kind, ref, trusted, grants) for cn, kind, ref, trusted, grants in AWS_IDENTITIES}
    ps = "arn:aws:sso:::permissionSet/ssoins-72231a2b3c4d5e6f/ps-ciamadmins01"
    _, ci_ref, ci_trust, ci_grants = rows["identity-ci"]
    _, group, _, admin_grants = rows["identity-admins"]
    _, bg_ref, bg_trust, _ = rows["identity-break-glass"]
    resources = [
        _res("managed", "aws_iam_openid_connect_provider", "github", {
            "arn": f"{ACCT}:oidc-provider/token.actions.githubusercontent.com",
            "url": "https://token.actions.githubusercontent.com", "client_id_list": ["sts.amazonaws.com"]}),
        _role("identity-ci", ci_ref, ci_trust, ci_grants),
        _res("managed", "aws_ssoadmin_permission_set", "ciam_admins", {
            "arn": ps, "name": "ciam-admins", "session_duration": "PT4H", "tags": {"Role": "identity-admins"}}),
        _res("managed", "aws_ssoadmin_permission_set_inline_policy", "ciam_admins", {
            "permission_set_arn": ps, "inline_policy": _policy(*_allows(admin_grants))}),
        _res("managed", "aws_ssoadmin_account_assignment", "ciam_admins", {
            "permission_set_arn": ps, "principal_id": group, "principal_type": "GROUP", "target_id": ACCOUNT,
            "target_type": "AWS_ACCOUNT"}),
        _role("identity-break-glass", bg_ref, bg_trust, (), managed=("arn:aws:iam::aws:policy/AdministratorAccess",))]
    return _dumps({"version": 4, "terraform_version": "1.9.5", "serial": 31, "lineage": "7a1d-ciam-landing-zone",
                   "outputs": {}, "resources": resources})


def _aws_dns(p):
    """The Resolver rules forwarding the environment's queries (the AD domain to the domain controllers)."""
    return [_res("managed", "aws_route53_resolver_rule", attrs["ciamProviderRef"], {
                "id": attrs["ciamProviderRef"], "name": cn, "rule_type": "FORWARD",
                "domain_name": f"{attrs['ciamForwardDomain']}.",
                "target_ip": [{"ip": ip, "port": 53} for ip in attrs["ciamForwardTarget"]]})
            for oc, cn, _, attrs in p["edge"] if oc == "ciamDnsForwarder"]


def source_state():
    """The source environment's Terraform state (format version 4), with the planted drift."""
    p = SOURCE
    subnets, instances, groups = _source_ids(p)
    resources = [*_aws_network(p, subnets), *_aws_servers(p, subnets, instances, groups, {"pf-engine-2": "m6i.xlarge"}),
                 *_aws_firewall(p, groups), *_aws_services(p, instances), *_aws_keys(p, rotation=False),
                 *_aws_monitoring(), *_drifted_source(p, subnets, groups), *_source_iam(), *_aws_dns(p)]
    return _dumps({"version": 4, "terraform_version": "1.9.5", "serial": 214, "lineage": "5e0c-ciam-prod",
                   "outputs": {}, "resources": resources})


# ------------------------------------------------------------------ target/prod: Azure CLI output
def _nic_id(cn):
    return f"{NET}/networkInterfaces/nic-{cn}"


def _subnet_id(ref):
    vnet, sub = ref.split("/")
    return f"{NET}/virtualNetworks/{vnet}/subnets/{sub}"


def _edge_subnets(p):
    """(binding name, role, provider ref, CIDR, zone) of the environment's edge subnets (the gateways', the proxies')."""
    return [(cn, role, attrs["ciamProviderRef"], attrs["ciamCidr"], None)
            for oc, cn, role, attrs in p["edge"] if oc == "ciamSubnetBinding"]


def _azure_network(p, extra_subnet):
    vnet = p["net"][1]
    subnets = [{"id": _subnet_id(ref), "name": ref.split("/")[1], "addressPrefix": cidr}
               for _, _, ref, cidr, _ in (*p["subnets"], *_edge_subnets(p))]
    return [{"id": f"{NET}/virtualNetworks/{vnet}", "name": vnet, "type": "Microsoft.Network/virtualNetworks",
             "resourceGroup": p["rg"], "location": "eastus2", "addressSpace": {"addressPrefixes": [p["net"][2]]},
             "subnets": [*subnets, extra_subnet]}]


def _azure_servers(p, resized):
    refs = {cn: ref for cn, _, ref, _, _ in p["subnets"]}
    vms = [{"id": f"{RG}/providers/Microsoft.Compute/virtualMachines/{cn}", "name": cn,
            "type": "Microsoft.Compute/virtualMachines", "zones": [zone], "privateIps": ip,
            "hardwareProfile": {"vmSize": resized.get(cn, size)}, "osProfile": {"computerName": cn},
            "storageProfile": {"imageReference": {"id": image}},
            "networkProfile": {"networkInterfaces": [{"id": _nic_id(cn)}]},
            "tags": {"Role": role, "Hostname": host, "Product": version, "ManagedBy": "opsdir"}}
           for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]]
    pools = {s[5]: f"{NET}/loadBalancers/lb-ciam-prod-{s[0]}/backendAddressPools/servers" for s in p["services"]}
    nics = [{"id": _nic_id(cn), "name": f"nic-{cn}", "type": "Microsoft.Network/networkInterfaces",
             "networkSecurityGroup": {"id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}"},
             "ipConfigurations": [{"name": "primary", "primary": True, "privateIPAddress": ip,
                                   "subnet": {"id": _subnet_id(refs[subnet])},
                                   "loadBalancerBackendAddressPools": [{"id": pools[role]}] if role in pools else []}]}
            for cn, role, host, ip, zone, size, image, subnet, version in p["servers"]]
    return vms, nics


def _azure_lb(cn, fqdn, ports, ip, pref):
    lb = f"{NET}/loadBalancers/lb-ciam-prod-{cn}"
    frontend = {"publicIPAddress": {"id": f"{NET}/publicIPAddresses/{pref}"}} if pref else \
        {"privateIPAddress": ip, "subnet": {"id": _subnet_id(f"{TARGET['net'][1]}/snet-ds")}}
    return {"id": lb, "name": f"lb-ciam-prod-{cn}", "type": "Microsoft.Network/loadBalancers",
            "frontendIPConfigurations": [{"name": "frontend", **frontend}],
            "backendAddressPools": [{"id": f"{lb}/backendAddressPools/servers", "name": "servers"}],
            "loadBalancingRules": [{"name": f"tcp-{port}", "frontendPort": port, "backendPort": port} for port in ports],
            "tags": {"Service": fqdn, "ManagedBy": "opsdir"}}


def _azure_record(fqdn, zone, ip, private):
    """An A record as `az network (private-)dns record-set a list` prints it."""
    name, kind = fqdn[:-len(zone) - 1], "privateDnsZones" if private else "dnszones"
    return {"id": f"{RG}/providers/Microsoft.Network/{kind}/{zone}/A/{name}", "name": name, "fqdn": f"{fqdn}.",
            "type": f"Microsoft.Network/{kind}/A", ("aRecords" if private else "ARecords"): [{"ipv4Address": ip}]}


def _azure_services(p):
    """(load balancers, public IPs, public A records, private A records) of the environment's service names."""
    services = [(cn, fqdn, zone, ports, ip, pref) for cn, _, fqdn, zone, _, _, ports, ip, pref, _ in p["services"]]
    return ([_azure_lb(cn, fqdn, ports, ip, pref) for cn, fqdn, zone, ports, ip, pref in services],
            [{"id": f"{NET}/publicIPAddresses/{pref}", "name": pref, "ipAddress": ip,
              "type": "Microsoft.Network/publicIPAddresses"} for cn, fqdn, zone, ports, ip, pref in services if pref],
            [_azure_record(fqdn, zone, ip, False) for cn, fqdn, zone, ports, ip, pref in services if pref],
            [_azure_record(fqdn, zone, ip, True) for cn, fqdn, zone, ports, ip, pref in services if not pref])


def _azure_nsgs(p, priorities):
    roles = list(dict.fromkeys(s[1] for s in p["servers"]))
    rules = [(trole, {"name": cn, "priority": priorities.get(cn, 100 + 10 * i), "direction": "Inbound",
                      "access": "Allow", "protocol": "Tcp", "sourceAddressPrefixes": cidrs,
                      "destinationPortRanges": [str(port) for port in ports],
                      "description": f"consumer {consumer}" if consumer else role})
             for i, (cn, role, cidrs, ports, trole, consumer, _) in enumerate(p["fw"])]
    return [{"id": f"{NET}/networkSecurityGroups/nsg-ciam-prod-{role}", "name": f"nsg-ciam-prod-{role}",
             "type": "Microsoft.Network/networkSecurityGroups", "resourceGroup": p["rg"],
             "securityRules": [r for t, r in rules if t == role],
             "networkInterfaces": [{"id": _nic_id(s[0])} for s in p["servers"] if s[1] == role],
             "tags": {"ManagedBy": "opsdir"}}
            for role in roles]


def _azure_vault(p):
    vault = p["key"][0].split("://", 1)[1].split("/")[0]
    key_name = p["key"][0].rsplit("/", 1)[1]
    url = f"https://{vault}.vault.azure.net"
    return ([{"id": f"{url}/secrets/{role}", "name": role, "attributes": {"enabled": True}, "tags": {}}
             for role in SECRET_ROLES],
            [{"kid": f"{url}/keys/{key_name}", "name": key_name, "attributes": {"enabled": True}}],
            {"key": {"kid": f"{url}/keys/{key_name}/4f1e", "kty": "RSA"}, "attributes": {"enabled": True}},
            [{"id": p["key"][1], "name": p["key"][1].rsplit("/", 1)[1], "type": "Microsoft.Compute/diskEncryptionSets",
              "activeKey": {"keyUrl": f"{url}/keys/{key_name}/4f1e"}}])


def target_inventory():
    """{file name: text} of the target environment's Azure CLI output and role map, with the planted drift."""
    p = TARGET
    mgmt = {"id": _subnet_id(f"{p['net'][1]}/snet-mgmt"), "name": "snet-mgmt", "addressPrefix": "10.60.9.0/28"}
    vms, nics = _azure_servers(p, {"ds-3": "Standard_D8s_v5"})
    lbs, ips, _, private = _azure_services(p)         # the public names are on the corporate DNS team's Infoblox
    nat_ip = {"id": f"{NET}/publicIPAddresses/pip-natgw-ciam-prod", "name": "pip-natgw-ciam-prod",
              "ipAddress": p["egress"][1][:-3], "type": "Microsoft.Network/publicIPAddresses"}
    secrets, keys, key_show, sets = _azure_vault(p)
    return {"vnets.json": _azure_network(p, mgmt), "vms.json": vms, "nics.json": nics, "lbs.json": lbs,
            "public-ips.json": [*ips, nat_ip],
            "private-dns-id.cloud.example-aero.test.json": private,
            "nsgs.json": _azure_nsgs(p, {"fw-idm-sync": 400}),
            "nat-gateways.json": [{"id": f"{NET}/natGateways/{p['egress'][0]}", "name": p["egress"][0],
                                   "type": "Microsoft.Network/natGateways",
                                   "publicIpAddresses": [{"id": nat_ip["id"]}]}],
            "disk-encryption-sets.json": sets, "kv-secrets.json": secrets, "kv-keys.json": keys,
            "kv-key-disk-cmk.json": key_show,
            "roles.json": {f"{p['net'][1]}/snet-mgmt": "subnet-mgmt"}}


# ------------------------------------------------------------------ standby/prod: Cloud Asset Inventory and gcloud
GAPI = "https://www.googleapis.com/compute/v1"
NUMBER = "481516234200"                                  # the standby project's number (Secret Manager names by it)
REGION_URL = f"{GAPI}/{PROJECT}/regions/us-central1"


def _asset(asset_type, data, name=None):
    """One asset as `gcloud asset export --content-type=resource` writes it (a line of JSON)."""
    service = asset_type.split("/")[0]
    return {"name": name or f"//{service}/{(data.get('selfLink') or data['name']).split('/v1/')[-1]}",
            "assetType": asset_type, "resource": {"version": "v1", "data": data}}


def _label(v):
    return re.sub(r"[^a-z0-9_-]", "-", (v or "").lower())[:63]


def _gcp_instance(server, full, resized):
    """An instance as Compute Engine reports it: Cloud Asset Inventory keeps only platform metadata keys (full=False),
    `gcloud compute instances list` all of them."""
    cn, role, host, ip, zone, size, image, subnet, version = server
    subnets = {name: ref for name, _, ref, _, _ in STANDBY["subnets"]}
    metadata = [{"key": "enable-oslogin", "value": "TRUE"},
                *(({"key": "ciam-role", "value": role}, {"key": "ciam-product", "value": version}) if full else ())]
    return {"kind": "compute#instance", "name": cn, "selfLink": f"{GAPI}/{PROJECT}/zones/{zone}/instances/{cn}",
            "zone": f"{GAPI}/{PROJECT}/zones/{zone}",
            "machineType": f"{GAPI}/{PROJECT}/zones/{zone}/machineTypes/{resized.get(cn, size)}",
            "hostname": host, "tags": {"items": [f"ciam-prod-{role}"]},
            "labels": {"role": _label(role), "product": _label(version), "managed_by": "opsdir"},
            "metadata": {"items": metadata},
            "disks": [{"boot": True, "source": f"{GAPI}/{PROJECT}/zones/{zone}/disks/{cn}"}],
            "networkInterfaces": [{"networkIP": ip, "network": f"{GAPI}/{STANDBY['net'][1]}",
                                   "subnetwork": f"{GAPI}/{subnets[subnet]}"}]}


def _gcp_firewalls(p):
    """The rendered rules (pinned priorities, '(name)' descriptions), each service's health-check probe rule, and the
    rule opened by hand."""
    network = f"{GAPI}/{p['net'][1]}"
    return [*({"kind": "compute#firewall", "name": f"ciam-prod-{cn}", "description": f"{role} ({cn})",
               "network": network, "direction": "INGRESS", "priority": 100 + 10 * i, "sourceRanges": cidrs,
               "targetTags": [f"ciam-prod-{trole}"], "allowed": [{"IPProtocol": "tcp", "ports": [str(x) for x in ports]}]}
              for i, (cn, role, cidrs, ports, trole, _, _) in enumerate(p["fw"])),
            *({"kind": "compute#firewall", "name": f"ciam-prod-{cn}-health-checks", "network": network,
               "description": f"Google Cloud health checks for {cn}", "direction": "INGRESS", "priority": 1000,
               "sourceRanges": ["35.191.0.0/16"] if ip.startswith("10.") else
               ["35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22"],
               "targetTags": [f"ciam-prod-{trole}"], "allowed": [{"IPProtocol": "tcp", "ports": [str(ports[0])]}]}
              for cn, _, _, _, _, trole, ports, ip, _, _ in p["services"]),
            {"kind": "compute#firewall", "name": "allow-iap-ssh", "description": "IAP SSH for the vendor (temporary)",
             "network": network, "direction": "INGRESS", "priority": 900, "sourceRanges": ["35.235.240.0/20"],
             "targetTags": ["ciam-prod-ds"], "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]}]


def _gcp_services(p):
    """(forwarding rules, backend services, record sets, get-health outputs by service) of the service names."""
    servers = p["servers"]
    rules, backends, records, health = [], [], [], {}
    for cn, _, fqdn, _, zref, trole, ports, ip, _, _ in p["services"]:
        name, targets = f"ciam-prod-{cn}", [s for s in servers if s[1] == trole]
        groups = {zone: f"{GAPI}/{PROJECT}/zones/{zone}/instanceGroups/{name}-{zone}" for zone in sorted({s[4] for s in targets})}
        backend = f"{REGION_URL}/backendServices/{name}"
        rules.append({"kind": "compute#forwardingRule", "name": name, "region": REGION_URL, "IPAddress": ip,
                      "ports": [str(x) for x in ports], "IPProtocol": "TCP", "backendService": backend,
                      "loadBalancingScheme": "INTERNAL" if ip.startswith("10.") else "EXTERNAL",
                      "selfLink": f"{REGION_URL}/forwardingRules/{name}", "labels": {"managed_by": "opsdir"}})
        backends.append({"kind": "compute#backendService", "name": name, "region": REGION_URL, "selfLink": backend,
                         "backends": [{"group": g, "balancingMode": "CONNECTION"} for g in groups.values()]})
        records.append(_asset("dns.googleapis.com/ResourceRecordSet",
                              {"name": f"{fqdn}.", "type": "A", "ttl": 300, "rrdatas": [ip]},
                              name=f"//dns.googleapis.com/{HOST}/managedZones/{zref}/rrsets/{fqdn}./A"))
        health[name] = [{"backend": g, "status": {"kind": "compute#backendServiceGroupHealth", "healthStatus": [
            {"instance": f"{GAPI}/{PROJECT}/zones/{zone}/instances/{s[0]}", "ipAddress": s[3], "port": ports[0],
             "healthState": "HEALTHY"} for s in targets if s[4] == zone]}} for zone, g in groups.items()]
    return rules, backends, records, health


def _gcp_references(p):
    """Secrets (named by project number), the disk key, the backup bucket, the audit topic and the engines' group."""
    key = p["key"][0].split("://", 1)[1]
    (mig, _, target, ref, image, size, least, runs, most, zones, _), = p["compute"]
    template = f"{GAPI}/{PROJECT}/global/instanceTemplates/{ref.rsplit('/', 1)[1]}-1"
    return [*(_asset("secretmanager.googleapis.com/Secret", {"name": f"projects/{NUMBER}/secrets/{role}",
                                                             "labels": {"role": role},
                                                             "replication": {"automatic": {}}})
              for role in SECRET_ROLES),
            _asset("cloudkms.googleapis.com/CryptoKey", {"name": key, "purpose": "ENCRYPT_DECRYPT",
                                                         "rotationPeriod": "7776000s", "labels": {"role": "disk-encryption"},
                                                         "versionTemplate": {"protectionLevel": "HSM",
                                                                             "algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION"}}),
            _asset("storage.googleapis.com/Bucket", {"kind": "storage#bucket", "name": p["backup"][5:],
                                                     "labels": {"role": "backup-target"}},
                   name=f"//storage.googleapis.com/{p['backup'][5:]}"),
            *(_asset("pubsub.googleapis.com/Topic", {"name": sref, "labels": {"role": role}})
              for _, role, sref, _ in p["streams"]),
            _asset("compute.googleapis.com/InstanceGroupManager", {
                "kind": "compute#instanceGroupManager", "name": ref.rsplit("/", 1)[1], "region": REGION_URL,
                "selfLink": f"{GAPI}/{ref}", "targetSize": runs, "versions": [{"instanceTemplate": template}],
                "distributionPolicy": {"zones": [{"zone": f"{GAPI}/{PROJECT}/zones/{z}"} for z in zones]}}),
            _asset("compute.googleapis.com/InstanceTemplate", {
                "kind": "compute#instanceTemplate", "name": template.rsplit("/", 1)[1], "selfLink": template,
                "properties": {"machineType": size, "labels": {"role": target},
                               "disks": [{"boot": True, "initializeParams": {"sourceImage": f"{GAPI}/{image}"}}]}}),
            _asset("compute.googleapis.com/Autoscaler", {
                "kind": "compute#autoscaler", "name": ref.rsplit("/", 1)[1], "region": REGION_URL,
                "selfLink": f"{REGION_URL}/autoscalers/{ref.rsplit('/', 1)[1]}", "target": f"{GAPI}/{ref}",
                "autoscalingPolicy": {"minNumReplicas": least, "maxNumReplicas": most}})]


def _gcp_monitoring():
    """What Cloud Monitoring and Logging run, from the standby's monitoring bindings."""
    def asset(oc, attrs):
        ref = attrs["ciamProviderRef"]
        if oc == "ciamAlertChannel":
            return _asset("monitoring.googleapis.com/NotificationChannel", {
                "name": ref, "type": "pagerduty", "displayName": "ciam-page", "labels": {"service_key": "**********"},
                "userLabels": {"role": "alerts-page"}})
        if oc == "ciamLogDestination":
            return _asset("logging.googleapis.com/LogBucket", {"name": ref, "retentionDays": attrs["ciamRetentionDays"],
                                                               "lifecycleState": "ACTIVE"})
        if oc == "ciamAlarmBinding":
            condition = ({"conditionMatchedLog": {"filter": 'logName:"pingfederate" AND "AUTHN_ATTEMPT" AND "FAILURE"'}}
                         if attrs["ciamMetric"] == "log query" else
                         {"conditionThreshold": {"filter": f'metric.type="{attrs["ciamMetric"]}" AND '
                                                           'resource.type="gce_instance"'}})
            return _asset("monitoring.googleapis.com/AlertPolicy", {
                "name": ref, "displayName": ref.rsplit("/", 1)[1], "conditions": [condition],
                "notificationChannels": [attrs["ciamNotifies"]], "userLabels": {"realizes": attrs["ciamRealizes"]}})
        return _asset("monitoring.googleapis.com/UptimeCheckConfig", {
            "name": ref, "displayName": "sso-login", "period": "300s", "userLabels": {"realizes": attrs["ciamRealizes"]}})
    return [asset(oc, attrs) for oc, _, _, attrs in MONITORING["standby"]]


def standby_inventory():
    """{file name: text} of the standby environment's Cloud Asset Inventory export and gcloud output, with the planted
    drift."""
    p = STANDBY
    resized = {"ds-2": "n2-standard-8"}
    rules, backends, records, health = _gcp_services(p)
    nat, address = p["egress"][0].split("/"), p["egress"][1][:-3]
    exported = [*(_asset("compute.googleapis.com/Instance", _gcp_instance(s, False, {})) for s in p["servers"]),
                *(_asset("compute.googleapis.com/Disk", {"kind": "compute#disk", "name": s[0], "sourceImage": f"{GAPI}/{s[6]}",
                                                         "selfLink": f"{GAPI}/{PROJECT}/zones/{s[4]}/disks/{s[0]}"})
                  for s in p["servers"]),
                *(_asset("compute.googleapis.com/Firewall", fw) for fw in _gcp_firewalls(p)),
                *(_asset("compute.googleapis.com/ForwardingRule", r) for r in rules),
                *(_asset("compute.googleapis.com/RegionBackendService", b) for b in backends),
                _asset("compute.googleapis.com/Address", {"kind": "compute#address", "name": "ciam-standby-nat-1",
                                                          "address": address, "region": REGION_URL,
                                                          "selfLink": f"{REGION_URL}/addresses/ciam-standby-nat-1"}),
                _asset("compute.googleapis.com/Router", {"kind": "compute#router", "name": nat[2], "region": REGION_URL,
                                                         "selfLink": f"{REGION_URL}/routers/{nat[2]}",
                                                         "nats": [{"name": nat[3], "natIpAllocateOption": "MANUAL_ONLY",
                                                                   "natIps": [f"{REGION_URL}/addresses/ciam-standby-nat-1"]}]}),
                *_gcp_references(p), *_gcp_monitoring(),
                _asset("iam.googleapis.com/ServiceAccount", {"name": f"{PROJECT}/serviceAccounts/ciam-servers@"
                                                                     "example-aero-ciam-standby.iam.gserviceaccount.com"})]
    host = [_asset("compute.googleapis.com/Network", {"kind": "compute#network", "name": p["net"][1].rsplit("/", 1)[1],
                                                      "selfLink": f"{GAPI}/{p['net'][1]}"}),
            *(_asset("compute.googleapis.com/Subnetwork", {"kind": "compute#subnetwork", "name": ref.rsplit("/", 1)[1],
                                                           "ipCidrRange": cidr, "network": f"{GAPI}/{p['net'][1]}",
                                                           "region": f"{GAPI}/{HOST}/regions/us-central1",
                                                           "selfLink": f"{GAPI}/{ref}",
                                                           **({"purpose": "REGIONAL_MANAGED_PROXY"}
                                                              if role == "subnet-edge" else {})})
              for _, role, ref, cidr, _ in (*p["subnets"], *_edge_subnets(p))),
            *records]
    iam, providers = _gcp_iam()
    return {"assets.jsonl": "".join(json.dumps(a, sort_keys=False) + "\n" for a in exported),
            "iam-policies.jsonl": "".join(json.dumps(a, sort_keys=False) + "\n" for a in iam),
            "pool-providers.json": _dumps(providers),
            "host-network.json": _dumps(host),
            "project.json": _dumps({"projectId": PROJECT.split("/")[1], "projectNumber": NUMBER,
                                    "name": PROJECT.split("/")[1], "lifecycleState": "ACTIVE"}),
            "instances.json": _dumps([_gcp_instance(s, True, resized) for s in p["servers"]]),
            **{f"health/{name}.json": _dumps(doc) for name, doc in health.items()}}


def _gcp_iam():
    """The standby's IAM policies as `gcloud asset export --content-type=iam-policy` writes them (by project number),
    its service accounts and the pipeline's pool provider: as the record holds them."""
    numbered = PROJECT.replace(PROJECT.split("/")[1], NUMBER)
    prefix = {"service-account": "serviceAccount", "federated": "serviceAccount", "group": "group", "user": "user"}

    def full(resource):
        if resource.startswith("projects/_/buckets/"):
            return f"//storage.googleapis.com/{resource.rsplit('/', 1)[1]}", "storage.googleapis.com/Bucket"
        if "/keyRings/" in resource:
            return f"//cloudkms.googleapis.com/{resource.replace(PROJECT, numbered)}", "cloudkms.googleapis.com/KeyRing"
        return f"//cloudresourcemanager.googleapis.com/{numbered}", "cloudresourcemanager.googleapis.com/Project"
    bindings = {}
    for cn, kind, ref, _, grants in GCP_IDENTITIES:
        for role, _, resource in (g.partition(" on ") for g in grants):
            bindings.setdefault(resource, {}).setdefault(role, []).append(f"{prefix[kind]}:{ref}")
    shown = {role: f"{cn} ({role})" for cn, _, role, *_ in PRINCIPAL_ROWS}
    accounts = [(cn, ref) for cn, kind, ref, _, _ in GCP_IDENTITIES if kind in ("service-account", "federated")]
    pool = f"projects/{NUMBER}/locations/global/workloadIdentityPools/ciam-prod-ci"
    ci = next((ref, trusted[0].split(" ", 1)[1]) for cn, _, ref, trusted, _ in GCP_IDENTITIES if cn == "identity-ci")
    return ([*({"name": full(r)[0], "assetType": full(r)[1],
                "iamPolicy": {"bindings": [{"role": role, "members": members} for role, members in roles.items()]}}
               for r, roles in bindings.items()),
             {"name": f"//iam.googleapis.com/{numbered}/serviceAccounts/{ci[0]}",
              "assetType": "iam.googleapis.com/ServiceAccount",
              "iamPolicy": {"bindings": [{"role": "roles/iam.workloadIdentityUser",
                                          "members": [f"principal://iam.googleapis.com/{pool}/subject/{ci[1]}"]}]}},
             *(_asset("iam.googleapis.com/ServiceAccount", {"email": ref, "name": f"{PROJECT}/serviceAccounts/{ref}",
                                                            "displayName": shown.get(cn)}) for cn, ref in accounts)],
            [{"name": f"{pool}/providers/github", "oidc": {"issuerUri": GITHUB}}])


def cloud_exports():
    """{path under exports/cloud/: text}: what each cloud reports its environment runs."""
    source, target, standby = (dn.split(",")[1].split("=")[1] for dn in (AWS, AZ, GCP))
    return {f"{source}/prod/terraform.tfstate": source_state(),
            f"{source}/prod/landing-zone.tfstate": landing_zone_state(),
            **{f"{target}/prod/{name}": _dumps(doc) for name, doc in target_inventory().items()},
            **{f"{standby}/prod/{name}": text for name, text in standby_inventory().items()}}
