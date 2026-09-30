"""What Azure says an environment runs, as the record's neutral resources (opsdir.core.inventory). Pure.

From Terraform state (terraform.tfstate, format version 4; hashicorp/azurerm), managed resources and data sources:

  azurerm_virtual_network                     -> network (role network): its name, first address space, resource group
  azurerm_subnet                              -> subnet <virtual network>/<subnet>
  azurerm_linux_virtual_machine,              -> server (name, role, hostname and product from its tags Name, Role,
    azurerm_windows_virtual_machine,             Hostname, Product; size, zone, image; the private address and subnet
    azurerm_virtual_machine                      of its primary network interface)
  azurerm_lb (+ rules, backend pools and      -> service: the DNS name of the A record holding its frontend address
    their NIC associations, azurerm_public_ip,   (or its tag Service), the zone, rule ports, the role of the VMs in
    azurerm_(private_)dns_a_record)              its pools, its private address or public IP (name and address)
  azurerm_network_security_rule and inline    -> firewall rules by name (inbound allow rules): sources, ports, protocol,
    azurerm_network_security_group rules         priority; the target role is that of the VMs whose interfaces or
                                                 subnets the group guards, else its tag Role, else its name's last part
  azurerm_key_vault_secret                    -> secret reference azkv://<vault>/<name>; its value is never read
  azurerm_key_vault_key                       -> key reference azkv-key://<vault>/keys/<name>: HSM or software, whether
    (+ azurerm_disk_encryption_set)              it rotates automatically, the disk encryption set that uses it
  azurerm_storage_container                   -> storage azblob://<account>/<container> (role from its metadata key role)
  azurerm_nat_gateway (+ its public IPs and   -> egress (by name): its public addresses
    prefixes)
Roles of resources the record doesn't have come from their tags Role (or BindingRole), or for storage containers from
their metadata (role). Subnets and individual security rules carry neither in Azure: their roles come from the
environment's role map (roles.json, opsdir.core.inventory), and without one new ones are named in the notices.
"""
from collections import Counter

from opsdir.core.contract import Importer
from opsdir.core.inventory import layout_import, per_file, resource
from opsdir_format_terraform.state import read_state

PROVIDER = "azure"

SKIPPED = ("random_password", "tls_private_key", "azurerm_key_vault_certificate", "azurerm_mssql_server",
           "azurerm_postgresql_flexible_server", "azurerm_mysql_flexible_server")  # secret values, or not modeled yet
VMS = ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine", "azurerm_virtual_machine")
ANY = ("*", "any", "internet", "0.0.0.0/0")


def _tags(a):
    return a.get("tags") or {}


def _role(a):
    t = _tags(a)
    return t.get("Role") or t.get("BindingRole")


def _of(found, *types):
    return [a for t, a in found if t in types]


def _first(xs):
    return (xs or (None,))[0]


def _low(x):
    return (x or "").lower()


def arm_segment(arm_id, after):
    """The ARM ID segment following `after` (case-insensitive): arm_segment('/…/vaults/kv-1', 'vaults') == 'kv-1'."""
    parts = (arm_id or "").split("/")
    return next((parts[i + 1] for i, p in enumerate(parts[:-1]) if p.lower() == after.lower()), None)


def _subnet_ref(arm_id):
    """<virtual network>/<subnet> of a subnet's ARM ID, the record's provider reference for it."""
    vnet, sub = arm_segment(arm_id, "virtualNetworks"), arm_segment(arm_id, "subnets")
    return f"{vnet}/{sub}" if vnet and sub else None


def _networks(found):
    return tuple(resource("network", a.get("name"), {"ciamCidr": _first(a.get("address_space")),
                                                     "ciamResourceGroup": a.get("resource_group_name")},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a) or "network")
                 for a in _of(found, "azurerm_virtual_network") if a.get("name"))


def _subnets(found):
    return tuple(resource("subnet", f"{a.get('virtual_network_name')}/{a.get('name')}",
                          {"ciamCidr": _first(a.get("address_prefixes")) or a.get("address_prefix")},
                          name=a.get("name"), role=_role(a))
                 for a in _of(found, "azurerm_subnet") if a.get("name") and a.get("virtual_network_name"))


def _nics(found):
    """{NIC id (lower case): (private address, subnet ref)} from each interface's primary IP configuration."""
    def primary(nic):
        configs = nic.get("ip_configuration") or ()
        return next((c for c in configs if c.get("primary")), _first(configs)) or {}
    return {_low(n.get("id")): (primary(n).get("private_ip_address") or n.get("private_ip_address"),
                                _subnet_ref(primary(n).get("subnet_id")))
            for n in _of(found, "azurerm_network_interface") if n.get("id")}


def _vm_nics(vm):
    return tuple(_low(i) for i in (*(vm.get("network_interface_ids") or ()), vm.get("primary_network_interface_id"))
                 if i)


def _image(vm):
    ref = _first(vm.get("source_image_reference") or vm.get("storage_image_reference")) or {}
    urn = ":".join(ref.get(k) or "" for k in ("publisher", "offer", "sku", "version")) if ref.get("offer") else None
    return vm.get("source_image_id") or ref.get("id") or urn


def _hostname(vm):
    """Tag Hostname, else the computer name when it is a full name (a short one would replace the record's FQDN)."""
    name = vm.get("computer_name") or (_first(vm.get("os_profile")) or {}).get("computer_name")
    return _tags(vm).get("Hostname") or (name if name and "." in name else None)


def _servers(found):
    nics = _nics(found)

    def one_vm(vm):
        ip, subnet = next((nics[n] for n in _vm_nics(vm) if n in nics), (None, None))
        return resource("server", vm.get("id"),
                        {"ciamPrivateIp": vm.get("private_ip_address") or ip,
                         "ciamZone": vm.get("zone") or _first(vm.get("zones")),
                         "ciamInstanceSize": vm.get("size") or vm.get("vm_size"), "ciamImageRef": _image(vm),
                         "ciamHostname": _hostname(vm), "ciamProductVersion": _tags(vm).get("Product")},
                        links={"ciamSubnet": subnet}, name=_tags(vm).get("Name") or vm.get("name"),
                        role=_tags(vm).get("Role"))
    return tuple(one_vm(vm) for vm in _of(found, *VMS))


def _nic_roles(found):
    """{NIC id (lower case): the Role tag of the VM using it}."""
    return {n: _tags(vm)["Role"] for vm in _of(found, *VMS) if _tags(vm).get("Role") for n in _vm_nics(vm)}


def _dns_records(found):
    """(fqdn, zone, addresses, target resource id) of each A record, public and private."""
    return tuple((a.get("zone_name") if a.get("name") == "@" else f"{a.get('name')}.{a.get('zone_name')}",
                  a.get("zone_name"), tuple(a.get("records") or ()), _low(a.get("target_resource_id")))
                 for a in _of(found, "azurerm_dns_a_record", "azurerm_private_dns_a_record")
                 if a.get("name") and a.get("zone_name"))


def _services(found):
    """A service per load balancer: its DNS name, zone, rule ports, the role behind its pools, its frontend."""
    pips = {_low(p.get("id")): p for p in _of(found, "azurerm_public_ip")}
    records, nic_roles = _dns_records(found), _nic_roles(found)

    def one_lb(lb):
        fe = _first(lb.get("frontend_ip_configuration")) or {}
        pip = pips.get(_low(fe.get("public_ip_address_id")))
        ip = fe.get("private_ip_address") if not fe.get("public_ip_address_id") else (pip or {}).get("ip_address")
        record = next((r for r in records if (ip and ip in r[2]) or (pip and r[3] == _low(pip.get("id")))), None)
        rules = [r for r in _of(found, "azurerm_lb_rule") if _low(r.get("loadbalancer_id")) == _low(lb.get("id"))]
        pools = {_low(p.get("id")) for p in _of(found, "azurerm_lb_backend_address_pool")
                 if _low(p.get("loadbalancer_id")) == _low(lb.get("id"))}
        roles = Counter(nic_roles.get(_low(a.get("network_interface_id")))
                        for a in _of(found, "azurerm_network_interface_backend_address_pool_association")
                        if _low(a.get("backend_address_pool_id")) in pools
                        and nic_roles.get(_low(a.get("network_interface_id"))))
        return resource("service", lb.get("id"), {
            "ciamFqdn": record[0] if record else _tags(lb).get("Service"),
            "ciamDnsZone": record[1] if record else None,
            "ciamPort": sorted({str(r.get("frontend_port")) for r in rules if r.get("frontend_port")}),
            "ciamTargetRole": roles.most_common(1)[0][0] if roles else None,
            "ciamFrontendIp": ip,
            "ciamProviderRef": (pip or {}).get("name")},
            name=lb.get("name"), role=_role(lb))
    return tuple(one_lb(lb) for lb in _of(found, "azurerm_lb"))


def _guarded_roles(found):
    """{NSG id (lower case): roles of the VMs it guards}, through NIC and subnet associations."""
    nics, nic_roles = _nics(found), _nic_roles(found)
    by_nic = [(_low(a.get("network_security_group_id")), nic_roles.get(_low(a.get("network_interface_id"))))
              for a in _of(found, "azurerm_network_interface_security_group_association")]
    by_subnet = [(_low(a.get("network_security_group_id")), nic_roles.get(n))
                 for a in _of(found, "azurerm_subnet_network_security_group_association")
                 for n, (_, subnet) in nics.items() if subnet and subnet == _subnet_ref(a.get("subnet_id"))]
    pairs = [(g, r) for g, r in (*by_nic, *by_subnet) if r]
    return {g: tuple(r for g2, r in pairs if g2 == g) for g in dict.fromkeys(g for g, _ in pairs)}


def _target_role(nsg, guarded):
    roles = Counter(guarded.get(_low(nsg.get("id"))) or ())
    return (roles.most_common(1)[0][0] if roles else None) or _role(nsg) or \
        (nsg.get("name") or "").rsplit("-", 1)[-1] or None


def _sources(rule):
    given = (*(rule.get("source_address_prefixes") or ()), rule.get("source_address_prefix"))
    return tuple(p for p in given if p)


def _cidr(prefix):
    """A source prefix as a CIDR: any source is 0.0.0.0/0, a bare address a /32; None for a service tag."""
    if prefix.lower() in ANY:
        return "0.0.0.0/0"
    if all(c in "0123456789./:" for c in prefix):
        return prefix if "/" in prefix else f"{prefix}/32"
    return None


def _ports(rule):
    given = (*(rule.get("destination_port_ranges") or ()), rule.get("destination_port_range"))
    return tuple(str(p) for p in given if p)


def _firewall(found):
    """(firewall rules, notices): inbound allow rules of the security groups, by rule name."""
    nsgs = {_low(g.get("id")): g for g in _of(found, "azurerm_network_security_group")}
    by_name = {(_low(g.get("resource_group_name")), _low(g.get("name"))): g for g in nsgs.values()}
    guarded = _guarded_roles(found)
    separate = [(by_name.get((_low(r.get("resource_group_name")), _low(r.get("network_security_group_name")))) or {}, r)
                for r in _of(found, "azurerm_network_security_rule")]
    inline = [(g, r) for g in nsgs.values() for r in g.get("security_rule") or ()]
    allowed = [(g, r) for g, r in (*separate, *inline) if r.get("name")
               and _low(r.get("direction")) == "inbound" and _low(r.get("access")) == "allow"]
    names = list(dict.fromkeys(r["name"] for _, r in allowed))

    def one_rule(name):
        mine = [(g, r) for g, r in allowed if r["name"] == name]
        protocol = next((_low(r.get("protocol")) for _, r in mine if _low(r.get("protocol")) in ("tcp", "udp")), None)
        return resource("firewall", name, {
            "ciamSourceCidr": sorted({_cidr(p) for _, r in mine for p in _sources(r) if _cidr(p)}),
            "ciamPort": sorted({p for _, r in mine for p in _ports(r) if p.isdigit()}, key=int),
            "ciamProtocol": protocol,
            "ciamRulePriority": next((r.get("priority") for _, r in mine if r.get("priority")), None),
            "ciamTargetRole": next((_target_role(g, guarded) for g, _ in mine if g), None)}, name=name)
    other = Counter(f"{_low(r.get('direction')) or '?'} {_low(r.get('access')) or '?'}"
                    for g, r in (*separate, *inline) if (g, r) not in allowed)
    tags = sorted({(r["name"], p) for _, r in allowed for p in _sources(r) if not _cidr(p)})
    ranges = sorted({(r["name"], p) for _, r in allowed for p in _ports(r) if not p.isdigit()})
    return (tuple(one_rule(n) for n in names),
            (*(f"security rules ({n} {kind}): not read (the record holds inbound allow rules)"
               for kind, n in sorted(other.items())),
             *(f"security rule {n}: source {p} is a service tag, not an address range; not recorded" for n, p in tags),
             *(f"security rule {n}: port {p} is not a single port; not recorded" for n, p in ranges)))


def _vault(a):
    return arm_segment(a.get("key_vault_id"), "vaults")


def _secrets(found):
    """Secret references from the secrets' vault and name alone; the value (and the version holding it) is never read."""
    return tuple(resource("secret", f"azkv://{_vault(a)}/{a.get('name')}",
                          {"ciamRefUri": f"azkv://{_vault(a)}/{a.get('name')}"},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a))
                 for a in _of(found, "azurerm_key_vault_secret") if _vault(a) and a.get("name"))


def _key_url(url):
    """(vault, key name) of a Key Vault key URL (https://<vault>.vault.azure.net/keys/<name>[/<version>])."""
    host, _, path = (url or "").partition("://")[2].partition("/")
    parts = path.split("/")
    return (host.split(".")[0].lower(), parts[1].lower()) if len(parts) > 1 and parts[0] == "keys" else None


def _keys(found):
    sets = {_key_url(s.get("key_vault_key_id")): s.get("id") for s in _of(found, "azurerm_disk_encryption_set")}

    def one_key(a):
        vault, name = _vault(a), a.get("name")
        policy = _first(a.get("rotation_policy")) or {}
        kind = a.get("key_type") or ""
        return resource("key", f"azkv-key://{vault}/keys/{name}", {
            "ciamRefUri": f"azkv-key://{vault}/keys/{name}",
            "ciamProtectionLevel": ("hsm" if kind.upper().endswith("-HSM") else "software") if kind else None,
            "ciamAutoRotate": ("TRUE" if policy.get("automatic") else "FALSE") if "rotation_policy" in a else None,
            "ciamProviderRef": sets.get((vault.lower(), name.lower()))},
            name=_tags(a).get("Name") or name, role=_role(a))
    return tuple(one_key(a) for a in _of(found, "azurerm_key_vault_key") if _vault(a) and a.get("name"))


def _metadata_role(a):
    """A container's role from its metadata (keys role or bindingrole, any case): containers carry metadata, not tags."""
    meta = {k.lower(): v for k, v in (a.get("metadata") or {}).items()}
    return meta.get("role") or meta.get("bindingrole")


def _storage(found):
    def account(a):
        return a.get("storage_account_name") or arm_segment(a.get("storage_account_id"), "storageAccounts")
    return tuple(resource("storage", a.get("id") or f"{account(a)}/{a.get('name')}",
                          {"ciamStorageRef": f"azblob://{account(a)}/{a.get('name')}"},
                          name=a.get("name"), role=_metadata_role(a))
                 for a in _of(found, "azurerm_storage_container") if account(a) and a.get("name"))


def _egress(found):
    """NAT gateways by name, with the public addresses and prefixes associated with them."""
    pips = {_low(p.get("id")): p.get("ip_address") for p in _of(found, "azurerm_public_ip")}
    prefixes = {_low(p.get("id")): p.get("ip_prefix") for p in _of(found, "azurerm_public_ip_prefix")}
    addresses = [(_low(a.get("nat_gateway_id")), f"{pips[_low(a.get('public_ip_address_id'))]}/32")
                 for a in _of(found, "azurerm_nat_gateway_public_ip_association")
                 if pips.get(_low(a.get("public_ip_address_id")))]
    ranges = [(_low(a.get("nat_gateway_id")), prefixes[_low(a.get("public_ip_prefix_id"))])
              for a in _of(found, "azurerm_nat_gateway_public_ip_prefix_association")
              if prefixes.get(_low(a.get("public_ip_prefix_id")))]
    return tuple(resource("egress", a.get("name"),
                          {"ciamCidr": sorted({c for g, c in (*addresses, *ranges) if g == _low(a.get("id"))})},
                          name=_tags(a).get("Name") or a.get("name"), role=_role(a))
                 for a in _of(found, "azurerm_nat_gateway") if a.get("name"))


def pairs_resources(pairs):
    """(resources, notices) of (Terraform resource type, attributes) pairs: what every Azure source is read into
    (Terraform state as it is; CLI output normalized to the same attribute names, opsdir_adapter_azure.cli)."""
    rules, rule_notices = _firewall(pairs)
    return ((*_networks(pairs), *_subnets(pairs), *_servers(pairs), *_services(pairs), *rules, *_secrets(pairs),
             *_keys(pairs), *_storage(pairs), *_egress(pairs)), rule_notices)


def state_resources(text):
    """(resources, notices) of an Azure Terraform state."""
    found, problem = read_state(text)
    if problem:
        return (), (problem,)
    pairs = [(r.type, r.attributes) for r in found]
    skipped = Counter(t for t, _ in pairs if t in SKIPPED)
    resources, notices = pairs_resources(pairs)
    return (resources,
            (*(f"{t} ({n}): not read (holds secret values, or isn't modeled yet)" for t, n in sorted(skipped.items())),
             *notices))


def read_terraform_state(files, d, patterns, at=None):
    """Imported: each environment's servers and bindings from the Azure Terraform states under <cloud>/<env>/."""
    return layout_import(files, d, PROVIDER, "Azure", per_file(state_resources), ".tfstate", "Terraform state",
                         "terraform.tfstate")


TERRAFORM_STATE = Importer("terraform-state", "Azure Terraform state (terraform.tfstate) under <cloud>/<env>/, as "
                                              "the environment's servers and bindings", read_terraform_state)
