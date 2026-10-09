"""Config files fixture data: files the platform keeps in the record, captured with opsdir's own capture (95-config-
files), and a bundle it deploys as it is (96-bundles). The PingFederate engines' run.properties takes its host name
from each environment's SSO service name and its admin password from the environment's secret reference (withheld at
capture); xTokenLifetimeMinutes lives in the default token manager's settings."""
from types import MappingProxyType

from opsdir.connectors.registry import secret_patterns
from opsdir.core.contract import SecretPattern
from opsdir.core.formats import JAVA_PROPERTIES, JSON
from opsdir.domains.configuration.bundles import bundle_entries, content_digest
from opsdir.domains.configuration.naming import BUNDLES, CONFIG_FILES, setting_dn
from opsdir.domains.configuration.record import file_entries
from .common import ou, owner, spec

RUN_PROPERTIES = """# PingFederate engine run.properties (Example Aero, synthetic)
pf.operational.mode=CLUSTERED_ENGINE
pf.engine.hostname=sso.example-aero.test
pf.https.port=9031
pf.admin.https.port=9999
pf.admin.pwd=Synthetic-Not-A-Real-Password-1
pf.log.eventdetail=false
"""
TOKEN_MANAGER = """{
  "id": "default-atm",
  "lifetimeMinutes": 60,
  "reuseExistingTokens": true
}
"""
# (name, format, repo path, deploy role, text, {locator: role#attribute}, deploy path or None)
FILES = (
    ("run.properties", JAVA_PROPERTIES, "pingfederate/bin/run.properties", "pf-engine", RUN_PROPERTIES,
     {"pf.engine.hostname": "pf-sso-service#ciamFqdn", "pf.admin.pwd": "pf-admin-password#ciamRefUri"},
     "/opt/pingfederate/bin/run.properties"),
    ("default-atm.json", JSON, "pingfederate/server/default/data/atm/default-atm.json", "pf-engine", TOKEN_MANAGER,
     {}, None),
)
LOGIN_TEMPLATES = MappingProxyType({
    "html.form.login.template.html": b"<!DOCTYPE html>\n<html><body><form>Sign in</form></body></html>\n",
    "assets/example-aero.css": b"body { font-family: sans-serif; }\n"})
TOKEN_LIFETIME = setting_dn("default-atm.json", "/lifetimeMinutes")     # where xTokenLifetimeMinutes lives
OPS_SCRIPTS = MappingProxyType({"nightly-export.sh": b"#!/bin/sh\n# MRO nightly export\n",
                                "ship-audit.sh": b"#!/bin/sh\n# audit shipping\n"})


def _patterns():
    return tuple(SecretPattern(name, pattern, desc) for name, pattern, _, desc in secret_patterns())


def _spec(file, e, extra):
    return spec(file, e.dn, e.classes, **{k: list(v) for k, v in e.attrs.items()}, **extra)


def _file_specs(name, fmt, repo_path, role, text, links, deploy_path):
    entries, _ = file_entries(fmt, text, name, repo_path, _patterns(), role, deploy_path)
    return tuple(_spec("95-config-files", e, {"ciamOwner": owner("ciam-platform")} if e.dn.startswith(f"cn={name},")
                       else {"ciamValueFrom": links.get(e.attrs["ciamLocator"][0])})
                 for e in entries)


def config_files():
    return (ou("95-config-files", "config-files", desc="Config files held in the record"),
            *(s for f in FILES for s in _file_specs(*f)))


def bundles():
    entry = bundle_entries("login-templates", "pingfederate/server/default/conf/template", "template",
                           content_digest(LOGIN_TEMPLATES), "html", "2026.09", "pf-engine")
    scripts = bundle_entries("ops-scripts", "ops/scripts", "script", content_digest(OPS_SCRIPTS), None, "2026.09",
                             None, "/opt/scripts")
    return (ou("96-bundles", "bundles", desc="Code, scripts, templates and packages deployed as they are"),
            _spec("96-bundles", entry, {"ciamOwner": owner("ciam-platform"),
                                        "description": "Branded sign-in pages"}),
            _spec("96-bundles", scripts, {"ciamOwner": owner("ciam-platform"),
                                          "description": "Operations scripts the servers' jobs run"}))
