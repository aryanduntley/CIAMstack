"""The naming context and its standard branches (data file 00-base)."""
from .common import R, ou, spec

BRANCHES = (("environments", "Clouds, environments, servers and bindings"),
            ("config", "Directory server configuration: declared (desired) and observed (snapshots)"),
            ("user-schema", "Records describing attributes of the user directory"),
            ("consumers", "Clients of the user directory, discovered from access logs"),
            ("acis", "Access control instructions on the user directory"),
            ("integrations", "Federation integrations (SAML / OIDC) and their claim maps"),
            ("certificates", "Certificates (public facts only — never keys)"),
            ("external-allowlists", "Allowlists in consumer and partner systems that contain our addresses"),
            ("runbooks", "Work instructions"),
            ("changes", "Change records mirrored from ITSM"),
            ("incidents", "Incidents and postmortems"),
            ("owners", "Teams, partners and vendors"))


def entries():
    return (spec("00-base", R, ["top", "domain"], dc="ciam-ops",
                 description="Operations directory for the external identity (CIAM) platform. Synthetic demo data."),
            *(ou("00-base", name, desc=desc) for name, desc in BRANCHES),
            ou("00-base", "declared", f"ou=config,{R}", "Desired, environment-neutral DS configuration"),
            ou("00-base", "observed", f"ou=config,{R}", "Read-only snapshots captured from live servers"))
