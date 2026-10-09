"""PingIDM adapter: render the deployment's configuration files.

  pingidm/conf/managed.json                          managed objects            (environment-neutral)
  pingidm/conf/sync.json                             sync mappings              (environment-neutral)
  pingidm/conf/schedule-<name>.json                  schedules                  (environment-neutral)
  pingidm/conf/provisioner.openicf-<name>.json       connectors: the host from the binding of the connector's target
                                                     role (in its JDBC URL when the import found it there: every
                                                     binding of the role, in host order), withheld credentials as
                                                     ${secret:<ref-uri>} of its credential role   (per environment)

The files follow IDM's conf/ layout but are not validated against a live IDM (milestone 7.2). A role the environment
doesn't bind renders as UNBOUND:<role>, and a withheld value no credential role supplies as ${withheld} (the planner
blocks on both).
"""

from opsdir.core.directory import children, one, rdn_value, values
from opsdir.core.environment import bound, secret_placeholder
from opsdir.core.jsondata import WITHHELD, held_json, indented, with_value, with_values
from opsdir.domains.infrastructure.external import is_jdbc_url, jdbc_hosts, role_hosts, with_jdbc_hosts
from .naming import CONNECTORS, MANAGED, MAPPINGS, SCHEDULES

FORMATS = (("pingidm/conf/*.json", "json"),)


def _config(e, attr="pingidmConfig"):
    return held_json(e, attr)


def _in_order(entries):
    return sorted(entries, key=lambda e: (int(one(e, "pingidmPosition", "0")), rdn_value(e)))


def managed_file(d):
    objects = _in_order(children(d, MANAGED, "pingidmManagedObject"))
    return {"objects": [{"name": rdn_value(o), **_config(o),
                         **({"schema": _config(o, "pingidmSchema")} if one(o, "pingidmSchema") else {})}
                        for o in objects]}


def sync_file(d):
    return {"mappings": [{"name": rdn_value(m), "source": one(m, "pingidmSource"), "target": one(m, "pingidmTarget"),
                          **_config(m)} for m in _in_order(children(d, MAPPINGS, "pingidmMapping"))]}


def schedule_files(d):
    return {f"pingidm/conf/schedule-{rdn_value(s)}.json":
            indented({"enabled": one(s, "pingidmEnabled", "TRUE") == "TRUE", **_config(s)})
            for s in children(d, SCHEDULES, "pingidmSchedule")}


def render_neutral(d):
    """The deployment's environment-neutral files: managed objects, mappings, schedules."""
    return {"pingidm/conf/managed.json": indented(managed_file(d)), "pingidm/conf/sync.json": indented(sync_file(d)),
            **schedule_files(d)}


def _hosted(m, config, role, port):
    """The connector's settings with environment m's host of its target role: in its JDBC URL when the import took
    the hosts from there (the URL holds none), else as configurationProperties.host."""
    url = (config.get("configurationProperties") or {}).get("url")
    if is_jdbc_url(url) and not jdbc_hosts(url):
        return with_value(config, "/configurationProperties/url", with_jdbc_hosts(url, role_hosts(m, role, port)))
    return with_value(config, "/configurationProperties/host", bound(m, role, "ciamFqdn"))


def provisioner(m, c):
    """A connector's provisioner file for environment m: its host and credentials from the environment's bindings."""
    target, credential = one(c, "pingidmTargetRole"), one(c, "pingidmCredentialRole")
    config = _config(c)
    hosted = _hosted(m, config, target, one(c, "pingidmPort")) if target else config
    filled = with_values(hosted, values(c, "pingidmWithheld"), secret_placeholder(m, credential) if credential
                         else WITHHELD)
    ref = {k: v for k, v in (("bundleName", one(c, "pingidmBundle")), ("bundleVersion", one(c, "pingidmBundleVersion")),
                             ("connectorName", one(c, "pingidmConnectorName"))) if v}
    return {"name": rdn_value(c), "connectorRef": ref, **filled}


def render_env(m, services):
    """Every connector's provisioner file, for this environment."""
    return {f"pingidm/conf/provisioner.openicf-{rdn_value(c)}.json": indented(provisioner(m, c))
            for c in children(m.d, CONNECTORS, "pingidmConnector")}
