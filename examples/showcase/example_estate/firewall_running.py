"""The lab's Panorama as it runs (milestone 6.2c): what `opsdir collect` saves from panorama-hq's XML API
(type=config&action=show, the running configuration) for the lab's device group CIAM-Lab and shared, as the
panos/running-config importer reads it (exports/panos/hq/lab/panorama-hq/api/). Pure: builds text.

It runs the lab's firewall rules as the PAN-OS add-on pushed them, with what the network team changed since (planted):
  fw-admin                  its source widened from the admin range's /28 to the team's hq-mgmt-net /24 (the import's
                            conflict; CHG-2048 keeps the record's /28: the next push restores it)
  fw-lb-ldaps               logging at session end switched off (record-owned: the next push restores it)
  fw-sso                    disabled
  fw-pf-cluster             a third destination, 10.80.4.13, beside the role's servers (a node nobody recorded)
  fw-pf-cluster-admin       not there (missing)
  vendor-tmp-ldaps          an unmarked allow from a vendor's range to ds-1 on LDAPS (unrecorded)
  opsdir-hq-lab-fw-old-monitoring   a rule carrying the lab's marker for a rule the record no longer holds
and in shared, the corporate apps' egress address group ciam-ldaps-servers (the external allowlist
hq-apps-egress-to-ldaps names it), which already holds the target's LDAPS address."""
from opsdir_adapter_panos.rules import name

from .infrastructure import LAB

DG = "device-group/CIAM-Lab"
DEVICE = "panorama-hq"
FOLDER = f"panos/hq/lab/{DEVICE}/api"
ENV = "hq-lab"
# the HQ apps' egress allowlist on the Panorama's shared objects: the source's and the target's LDAPS addresses
ALLOWLIST_GROUP = "ciam-ldaps-servers"
ALLOWLIST_MEMBERS = (("ciam-ldaps-source", "10.20.1.100/32"), ("ciam-ldaps-target", "10.60.1.100/32"))
WIDENED = ("fw-admin", "hq-mgmt-net", "10.80.9.0/24")
NO_LOG = "fw-lb-ldaps"
DISABLED = "fw-sso"
EXTRA_DESTINATION = ("fw-pf-cluster", "10.80.4.13")
MISSING = "fw-pf-cluster-admin"


def _members(tag, names):
    return f"<{tag}>{''.join(f'<member>{n}</member>' for n in names)}</{tag}>"


def _uuid(i):
    return f"6a1c0000-0000-4000-8000-{i:012d}"


def _rule(i, rule_name, sources, destinations, services, description, extra=""):
    return (f'<entry name="{rule_name}" uuid="{_uuid(i)}">{_members("from", ("any",))}{_members("to", ("any",))}'
            f"{_members('source', sources)}{_members('destination', destinations)}{_members('service', services)}"
            f"{_members('application', ('any',))}<action>allow</action>{extra}"
            f"<description>{description}</description></entry>")


def _servers(role):
    return tuple(s for s in LAB["servers"] if s[1] == role)


def _lab_rule(i, fw):
    cn, _, cidrs, ports, role = fw[:5]
    sources = (WIDENED[1],) if cn == WIDENED[0] else tuple(name(c.replace("/", "_")) for c in cidrs)
    destinations = (*(name(f"{ENV}-{s[0]}") for s in _servers(role)),
                    *((EXTRA_DESTINATION[1],) if cn == EXTRA_DESTINATION[0] else ()))
    extra = ("<log-end>no</log-end>" if cn == NO_LOG else "") + ("<disabled>yes</disabled>" if cn == DISABLED else "")
    return _rule(i, name(f"{ENV}-{cn}"), sources, destinations, tuple(name(f"tcp-{p}") for p in ports),
                 f"opsdir hq/lab: {cn} -&gt; role {role}", extra)


def _rules():
    lab = [_lab_rule(i, fw) for i, fw in enumerate(LAB["fw"], 1) if fw[0] != MISSING]
    return (*lab,
            _rule(90, "vendor-tmp-ldaps", ("192.0.2.0/24",), (name(f"{ENV}-ds-1"),), (name("tcp-1636"),),
                  "temporary vendor access (network team)"),
            _rule(91, name(f"{ENV}-fw-old-monitoring"), ("10.80.9.0/28",), (name(f"{ENV}-mon-1"),),
                  (name("tcp-9090"),), "opsdir hq/lab: fw-old-monitoring -&gt; role monitoring"))


def _address(n, value):
    return f'<entry name="{n}"><ip-netmask>{value}</ip-netmask></entry>'


def _addresses():
    ranges = dict.fromkeys(c for fw in LAB["fw"] for c in fw[2])
    return (*(_address(name(c.replace("/", "_")), c) for c in ranges),
            *(_address(name(f"{ENV}-{s[0]}"), s[3]) for s in LAB["servers"]),
            _address(WIDENED[1], WIDENED[2]))


def _services():
    ports = dict.fromkeys((*(p for fw in LAB["fw"] for p in fw[3]), 9090))
    return tuple(f'<entry name="{name(f"tcp-{p}")}"><protocol><tcp><port>{p}</port></tcp></protocol></entry>'
                 for p in ports)


def _answer(holder, entries):
    if not entries:
        return '<response status="success" code="7"><result/></response>\n'
    return (f'<response status="success" code="19"><result total-count="{len(entries)}" count="{len(entries)}">'
            f"<{holder}>{''.join(entries)}</{holder}></result></response>\n")


def panorama_exports():
    """{path under exports/: text}: the XML API answers `opsdir collect` saves for the lab's Panorama."""
    shared_group = (f'<entry name="{ALLOWLIST_GROUP}"><static>'
                    f"{''.join(f'<member>{n}</member>' for n, _ in ALLOWLIST_MEMBERS)}</static></entry>",)
    parts = {DG: {"pre-rulebase": ("rules", _rules()), "post-rulebase": ("rules", ()),
                  "address": ("address", _addresses()), "address-group": ("address-group", ()),
                  "service": ("service", _services()), "service-group": ("service-group", ())},
             "shared": {"pre-rulebase": ("rules", ()), "post-rulebase": ("rules", ()),
                        "address": ("address", tuple(_address(n, v) for n, v in ALLOWLIST_MEMBERS)),
                        "address-group": ("address-group", shared_group), "service": ("service", ()),
                        "service-group": ("service-group", ())}}
    return {f"{FOLDER}/{scope}/{family}.xml": _answer(holder, entries)
            for scope, families in parts.items() for family, (holder, entries) in families.items()}
