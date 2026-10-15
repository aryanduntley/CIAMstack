"""The round trip (connectors.roundtrip, ReadBack prepare): the render's play and inventory turned into the running
configuration pushing them would leave (a running-config.xml per appliance, in the environment's folder), which the
read-back (importer.py) reads against the record the render was made from: a faithful render changes nothing but what a
read observes. Pure."""
from xml.sax.saxutils import escape, quoteattr

import yaml

from .render import GROUP
from .running import SNAPSHOT

PLAY = "ansible/panos.yml"
INVENTORY = "ansible/inventory/panos.yml"


def _load(text):
    """A rendered YAML file's documents' first value (its !unsafe tags read as the plain strings they mark)."""
    return yaml.safe_load(text.replace("!unsafe ", ""))


def _members(tag, names):
    return f"<{tag}>{''.join(f'<member>{escape(str(n))}</member>' for n in names)}</{tag}>"


def _entry(name, body):
    return f"<entry name={quoteattr(str(name))}>{body}</entry>"


def _rule(r):
    return _entry(r["rule_name"], "".join((
        _members("from", ("any",)), _members("to", ("any",)), _members("source", r["source_ip"]),
        _members("destination", r["destination_ip"]), _members("service", r["service"]),
        _members("application", ("any",)), "<action>allow</action>", "<log-end>yes</log-end>",
        f"<description>{escape(r['description'])}</description>")))


def _address(a):
    kind = a["address_type"]
    return _entry(a["name"], f"<{kind}>{escape(str(a['value']))}</{kind}>")


def _service(s):
    proto, port = s["protocol"], escape(str(s["destination_port"]))
    return _entry(s["name"], f"<protocol><{proto}><port>{port}</port></{proto}></protocol>")


def _objects(found):
    return (f"<address>{''.join(_address(a) for a in found['addresses'])}</address>"
            f"<service>{''.join(_service(s) for s in found['services'])}</service>")


def running_config(host, found):
    """The <config> document a push of the play's variables (found: addresses, services, rules) to one inventory host
    (its ciam_panos_device_group or ciam_panos_vsys) leaves running."""
    rules = f"<security><rules>{''.join(_rule(r) for r in found['rules'])}</rules></security>"
    if "ciam_panos_device_group" in host:
        scope = _entry(host["ciam_panos_device_group"], f"<pre-rulebase>{rules}</pre-rulebase>{_objects(found)}")
        place = f"<device-group>{scope}</device-group>"
    else:
        scope = _entry(host.get("ciam_panos_vsys", "vsys1"), f"<rulebase>{rules}</rulebase>{_objects(found)}")
        place = f"<vsys>{scope}</vsys>"
    return f'<config><devices>{_entry("localhost.localdomain", place)}</devices></config>'


def running_from_render(files, d, environment):
    """{<cloud>/<env>/<appliance>/running-config.xml: text}: what pushing the rendered play leaves on each Panorama or
    firewall of the rendered inventory (files: the render's ansible/panos.yml and ansible/inventory/panos.yml)."""
    if PLAY not in files or INVENTORY not in files:
        return {}
    found = _load(files[PLAY])[0]["vars"]["ciam_panos"]
    hosts = ((_load(files[INVENTORY]) or {}).get("all", {}).get("children", {}).get(GROUP, {}).get("hosts") or {})
    return {f"{environment}/{name}/{SNAPSHOT}": running_config(host, found) for name, host in hosts.items()}
