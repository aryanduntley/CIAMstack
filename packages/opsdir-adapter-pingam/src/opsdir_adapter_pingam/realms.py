"""AM realms as identity services, and where a realm's things are: its endpoint paths, its directory in an Amster
export. Pure."""
from opsdir.core.directory import is_a, one
from opsdir.domains.federation.services import identity_services

ROOT = "/"
SERVER_ROLES = ("am",)               # ciamServerRole / ciamTargetRole values this adapter defines
SUCCESS_NODE = "70e691a5-1e33-4ac3-a356-e7b6d60d92e0"      # AM's static nodes that end a journey
FAILURE_NODE = "e301438c-0bd0-429c-ab0c-66126501069a"
STATIC_NODES = (SUCCESS_NODE, FAILURE_NODE)


def realm_path(service):
    return one(service, "pingamRealmPath") or ROOT


def realms(d):
    """The identity services AM serves (servers of role am), each a realm."""
    return identity_services(d, SERVER_ROLES)


def recorded_realms(d):
    """Every identity service recorded as an AM realm (whoever serves it), for placing what an export holds."""
    return tuple(s for s in identity_services(d) if is_a(s, "pingamRealm"))


def realm_named(d, path):
    return next((s for s in recorded_realms(d) if realm_path(s) == path), None)


def _segments(path):
    return tuple(p for p in path.strip("/").split("/") if p)


def export_dir(path):
    """The realm's directory in an Amster export: realms/root, realms/root-customers, ..."""
    return "realms/" + "-".join(("root", *_segments(path)))


def oauth2_path(path):
    """AM's OAuth 2.0 / OIDC endpoint base for a realm: /am/oauth2[/realms/root/realms/<name>...]."""
    return "/am/oauth2" + ("" if path == ROOT else "/realms/root" + "".join(f"/realms/{s}" for s in _segments(path)))


def meta_alias(path, what):
    """A SAML endpoint path of the realm's hosted IdP: /am/<what>/metaAlias[/<realm>]/idp."""
    return f"/am/{what}/metaAlias{'' if path == ROOT else path}/idp"
