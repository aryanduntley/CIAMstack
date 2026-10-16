"""SiteMinder's agent files as plain settings, and every name the adapter reads of them, as data. Pure.

UNVERIFIED FOR 12.8 / 12.9 like xps.py: the names come from Broadcom's archived Web Agent 12.52 and Secure Proxy
Server 12.52 guides and knowledge-base articles quoting 12.8 files (research note of task 549; README, Known limits):

  WebAgent.conf, SmHost.conf, LocalConfig.conf   name="value" lines (a name may repeat: a multi-valued setting), '#'
                                                 comments, names case-insensitive
      EnableWebAgent="YES"
      AgentConfigObject="crew-aco"               the agent configuration object (ACO) in the policy store
      HostConfigFile="/opt/ca/webagent/config/SmHost.conf"
      policyserver="10.0.1.5,44441,44442,44443"  SmHost.conf, repeated per policy server
  server.conf (an Access Gateway's)              section tags around name="value" lines; not XML
      <VirtualHost name="parts">
        hostnames="parts.example.test,parts-alt.example.test"
        <WebAgent>
          sminitfile="/opt/ca/secure-proxy/proxy-engine/conf/partsagent/WebAgent.conf"
        </WebAgent>
      </VirtualHost>
      <ServiceDispatcher>
        rules_file="/opt/ca/secure-proxy/proxy-engine/conf/proxyrules.xml"     one rules file for every virtual host
      </ServiceDispatcher>

An agent's settings are its ACO's (the policy store's, as the ACO's Parameters "<name>=<value>" values) overlaid by its
LocalConfig.conf where the ACO allows it (AllowLocalConfig: no by default, yes for all, or the names it lists).
"""
import re
from functools import reduce
from types import MappingProxyType
from typing import NamedTuple

# The files of a server's folder, by kind (their names case aside)
WEBAGENT_CONF, SMHOST_CONF, LOCAL_CONF, SERVER_CONF, PROXY_RULES = (
    "webagent.conf", "smhost.conf", "localconfig.conf", "server.conf", "proxyrules.xml")
# What each setting read is called in the files (case aside)
NAMES = MappingProxyType({
    "enabled": "EnableWebAgent", "aco": "AgentConfigObject", "host_config_file": "HostConfigFile",
    "local_config_file": "LocalConfigFile", "server_path": "ServerPath",
    "trusted_host": "hostname", "hco": "hostconfigobject", "policy_server": "policyserver",
    "default_agent": "DefaultAgentName", "agent_name": "AgentName", "allow_local": "AllowLocalConfig",
    "ignore_ext": "IgnoreExt", "ignore_url": "IgnoreUrl"})
MAPPED = tuple(NAMES[k] for k in ("enabled", "aco", "trusted_host", "hco", "policy_server", "default_agent",
                                  "agent_name"))     # the settings an agent instance has attributes of its own for
# server.conf's sections and settings
VIRTUAL_HOST, HOSTNAMES, WEBAGENT_SECTION, INIT_FILE = "VirtualHost", "hostnames", "WebAgent", "sminitfile"
VIRTUAL_HOST_DEFAULTS, DISPATCHER, RULES_FILE = "VirtualHostDefaults", "ServiceDispatcher", "rules_file"
DEFAULT_AGENT_FILE = "proxy-engine/conf/defaultagent/WebAgent.conf"    # a virtual host naming no file of its own
ACO_PARAMETERS = "Parameters"    # the ACO's settings in the export ("<name>=<value>" values)
LOCAL_LABEL = "LocalConfig.conf"  # what an instance's other settings (smConfig) file LocalConfig.conf's under
ALL, NONE = ("*",), ()           # which local settings an ACO allows

# A server.conf section: its tag's name and attributes, its settings in order, the sections inside it
Section = NamedTuple("Section", [("name", str), ("attrs", tuple), ("settings", tuple), ("children", tuple)])

_OPEN = re.compile(r'^<([A-Za-z][\w.-]*)((?:\s+[\w.-]+\s*=\s*"[^"]*")*)\s*>$')
_CLOSE = re.compile(r"^</([A-Za-z][\w.-]*)\s*>$")
_ATTR = re.compile(r'([\w.-]+)\s*=\s*"([^"]*)"')
_SETTING = re.compile(r'^([A-Za-z][\w.-]*)\s*=\s*(?:"([^"]*)"|(.*?))\s*$')
_AGENT_NAME = re.compile(r"^agentname\d*$", re.IGNORECASE)


def _closed(stack):
    """The stack with its innermost section closed into its parent."""
    return (*stack[:-2], stack[-2]._replace(children=(*stack[-2].children, stack[-1])))


def _step(stack, line):
    text = line.strip()
    if not text or text.startswith("#"):
        return stack
    opened, closed, setting = _OPEN.match(text), _CLOSE.match(text), _SETTING.match(text)
    if opened:
        return (*stack, Section(opened.group(1), tuple(_ATTR.findall(opened.group(2))), (), ()))
    if closed:
        return _closed(stack) if len(stack) > 1 else stack
    if setting:
        value = setting.group(2) if setting.group(2) is not None else setting.group(3)
        return (*stack[:-1], stack[-1]._replace(settings=(*stack[-1].settings, (setting.group(1), value))))
    return stack


def _all_closed(stack):
    return stack[0] if len(stack) == 1 else _all_closed(_closed(stack))


def sections(text):
    """The Section of a whole file (name ''): its settings and sections, an unclosed section closed at the end."""
    return _all_closed(reduce(_step, text.splitlines(), (Section("", (), (), ()),)))


def settings(text):
    """((name, value), ...) of a name="value" file, in order (a name may repeat)."""
    return sections(text).settings


def named(pairs, name):
    """The values of the settings called name (case aside), in order."""
    return tuple(v for n, v in pairs if n.lower() == name.lower())


def first(pairs, name):
    found = named(pairs, name)
    return found[0] if found else None


def attr(section, name):
    return next((v for n, v in section.attrs if n.lower() == name.lower()), None)


def within(section, name):
    """Every section called name inside section, depth first."""
    return tuple(x for c in section.children for x in ((c,) if c.name.lower() == name.lower() else ())
                 + within(c, name))


def settings_outside(section, name):
    """The settings of section and the sections inside it, those inside sections called name left out."""
    return (*section.settings, *(p for c in section.children if c.name.lower() != name.lower()
                                 for p in settings_outside(c, name)))


def parameters(values):
    """((name, value), ...) of an ACO's "<name>=<value>" parameters."""
    return tuple((n.strip(), v.strip().strip('"')) for n, _, v in (p.partition("=") for p in values) if n.strip())


def listed(values):
    """The items of comma-separated values (IgnoreExt=".gif,.png"), each once, in order."""
    return tuple(dict.fromkeys(x.strip() for v in values for x in v.split(",") if x.strip()))


def agent_names(pairs):
    """The agent identities settings name: each AgentName (and AgentName1, ...) "<name>,<address>" mapping's name, then
    DefaultAgentName (AgentName maps requests to identities by address; DefaultAgentName answers the rest)."""
    mapped = tuple(v.split(",", 1)[0].strip() for n, v in pairs if _AGENT_NAME.match(n))
    return tuple(dict.fromkeys(x for x in (*mapped, *named(pairs, NAMES["default_agent"])) if x))


def allowed_local(aco):
    """Which LocalConfig.conf settings an ACO's parameters let override it: ALL, NONE, or the names it lists."""
    value = (first(aco, NAMES["allow_local"]) or "no").strip()
    if value.lower() in ("no", "false", ""):
        return NONE
    return ALL if value.lower() in ("yes", "true") else tuple(n.lower() for n in listed((value,)))


def is_allowed(allowed, name):
    return allowed == ALL or name.lower() in allowed


def effective(central, local, allowed):
    """An agent's settings: its ACO's (central), each name the ACO allows its LocalConfig.conf (local) to set replaced
    by the local values."""
    overridden = {n.lower() for n, _ in local if is_allowed(allowed, n)}
    return (*((n, v) for n, v in central if n.lower() not in overridden),
            *((n, v) for n, v in local if is_allowed(allowed, n)))


def _components(path):
    return tuple(p.lower() for p in path.replace("\\", "/").split("/") if p)


def matching(paths, configured):
    """The path among paths (a folder's files) that a path a file names on the server (configured) is: the one sharing
    the longest tail of path components with it, its file name at least; None when none has its file name."""
    want = _components(configured or "")

    def shared(p):
        mine = _components(p)
        return next((i for i in range(min(len(mine), len(want)), 0, -1) if mine[-i:] == want[-i:]), 0)
    found = sorted(((shared(p), p) for p in paths), key=lambda x: (-x[0], x[1]))
    return found[0][1] if found and found[0][0] else None


def file_name(path):
    return _components(path)[-1] if _components(path) else ""
