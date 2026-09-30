"""What the clouds report the environments run (pure: builds text). Generated from the same fixture data as the record,
so each export matches it except for the drift planted here, which `opsdir import --dry-run` shows:

  source/prod, AWS Terraform state (terraform.tfstate):
    - pf-engine-2 resized in the console (m6i.large -> m6i.xlarge)
    - an untagged bastion instance nobody recorded
    - a hand-opened security group rule, "temporary vendor access", 10.99.0.0/16 to LDAPS
    - the disk key's automatic rotation switched off
  target/prod, Azure CLI output (az … -o json), with a role map:
    - fw-idm-sync's NSG priority changed in the portal (130 -> 400)
    - ds-3 resized (Standard_D4s_v5 -> Standard_D8s_v5)
    - a management subnet added in the portal, snet-mgmt; roles.json gives it the role subnet-mgmt
"""
import hashlib
import json

from .common import AWS, AZ
from .infrastructure import SECRET_ROLES, SOURCE, TARGET

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
    return [_res("managed", "aws_lb", cn, {"arn": arn, "name": f"ciam-prod-{cn}", "internal": internal,
                                           "dns_name": dns, "subnet_mapping": [
                                               {"private_ipv4_address": ip} if internal else {"allocation_id": pref}]}),
            *(() if internal else (_res("data", "aws_eip", cn, {"allocation_id": pref, "public_ip": ip}),)),
            _res("managed", "aws_route53_record", cn, {"name": fqdn, "zone_id": zref, "type": "A",
                                                       "alias": [{"name": dns, "zone_id": "Z26RNL4JYFTOTI"}]}),
            *(r for port in ports for r in (
                _res("managed", "aws_lb_target_group", f"{cn}_{port}", {"arn": group(port), "port": port}),
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
                                                         "arn": f"arn:aws:s3:::{p['backup'][len('s3://'):]}"})]


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


def source_state():
    """The source environment's Terraform state (format version 4), with the planted drift."""
    p = SOURCE
    subnets, instances, groups = _source_ids(p)
    resources = [*_aws_network(p, subnets), *_aws_servers(p, subnets, instances, groups, {"pf-engine-2": "m6i.xlarge"}),
                 *_aws_firewall(p, groups), *_aws_services(p, instances), *_aws_keys(p, rotation=False),
                 *_drifted_source(p, subnets, groups)]
    return _dumps({"version": 4, "terraform_version": "1.9.5", "serial": 214, "lineage": "5e0c-ciam-prod",
                   "outputs": {}, "resources": resources})


# ------------------------------------------------------------------ target/prod: Azure CLI output
def _nic_id(cn):
    return f"{NET}/networkInterfaces/nic-{cn}"


def _subnet_id(ref):
    vnet, sub = ref.split("/")
    return f"{NET}/virtualNetworks/{vnet}/subnets/{sub}"


def _azure_network(p, extra_subnet):
    vnet = p["net"][1]
    subnets = [{"id": _subnet_id(ref), "name": ref.split("/")[1], "addressPrefix": cidr}
               for _, _, ref, cidr, _ in p["subnets"]]
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
    lbs, ips, public, private = _azure_services(p)
    nat_ip = {"id": f"{NET}/publicIPAddresses/pip-natgw-ciam-prod", "name": "pip-natgw-ciam-prod",
              "ipAddress": p["egress"][1][:-3], "type": "Microsoft.Network/publicIPAddresses"}
    secrets, keys, key_show, sets = _azure_vault(p)
    return {"vnets.json": _azure_network(p, mgmt), "vms.json": vms, "nics.json": nics, "lbs.json": lbs,
            "public-ips.json": [*ips, nat_ip], "dns-example-aero.test.json": public,
            "private-dns-id.cloud.example-aero.test.json": private,
            "nsgs.json": _azure_nsgs(p, {"fw-idm-sync": 400}),
            "nat-gateways.json": [{"id": f"{NET}/natGateways/{p['egress'][0]}", "name": p["egress"][0],
                                   "type": "Microsoft.Network/natGateways",
                                   "publicIpAddresses": [{"id": nat_ip["id"]}]}],
            "disk-encryption-sets.json": sets, "kv-secrets.json": secrets, "kv-keys.json": keys,
            "kv-key-disk-cmk.json": key_show,
            "roles.json": {f"{p['net'][1]}/snet-mgmt": "subnet-mgmt"}}


def cloud_exports():
    """{path under exports/cloud/: text}: what each cloud reports its environment runs."""
    source, target = AWS.split(",")[1].split("=")[1], AZ.split(",")[1].split("=")[1]
    return {f"{source}/prod/terraform.tfstate": source_state(),
            **{f"{target}/prod/{name}": _dumps(doc) for name, doc in target_inventory().items()}}
