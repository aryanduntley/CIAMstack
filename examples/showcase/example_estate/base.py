"""The naming context and its standard branches (data file 00-base)."""
from .common import R, ou, spec

BRANCHES = (("environments", "Clouds, environments, servers and bindings"),
            ("config", "Directory server configuration: declared (desired) and observed (snapshots)"),
            ("user-schema", "Records describing attributes of the user directory"),
            ("consumers", "Clients of the user directory, discovered from access logs"),
            ("acis", "Access control instructions on the user directory"),
            ("identity-services", "The platform's own identity provider / OpenID provider"),
            ("integrations", "Federation integrations (SAML / OIDC) and their claim maps"),
            ("certificates", "Certificates (public facts only — never keys)"),
            ("credentials", "Keys and secrets as metadata; each environment binds them to where it keeps the material"),
            ("external-allowlists", "Allowlists in consumer and partner systems that contain our addresses"),
            ("runbooks", "Work instructions"),
            ("changes", "Change records mirrored from ITSM"),
            ("incidents", "Incidents and postmortems"),
            ("restore-tests", "Restore tests: one entry per restore someone did, and what it proved"),
            ("recovery", "Recovery objectives: how long each protected role may be down, how much it may lose"),
            ("failover-drills", "Failover drills: one entry per failover someone did, and how it went"),
            ("owners", "Teams, partners and vendors"),
            ("tag-policy", "Tag policy: the tags every rendered resource carries and where their values come from"),
            ("reporting-obligations", "Incident reporting obligations the estate is held to (a regime's clock, "
                                      "authority, filer, certificate, preservation)"),
            ("poam", "Plan of action and milestones: the known weaknesses and how each is corrected"),
            ("exceptions", "Approved deviations: accepted risks, false positives, operational requirements"),
            ("assessments", "Compliance assessments of the environments: score and status"),
            ("authorizations", "Cloud offerings' authorizations (FedRAMP, DoD): levels, status, the services in scope"),
            ("boundaries", "The operator's system boundaries: its system security plans and the environments inside"),
            ("responsibilities", "Who meets each control under a cloud authorization (its responsibility matrix)"),
            ("custom-schema", "Fields and record types the operator defines"),
            ("feature-flags", "Feature switches of the login experience (a custom record type)"))


def entries():
    return (spec("00-base", R, ["top", "domain"], dc="ciam-ops",
                 description="Operations directory for the external identity (CIAM) platform. Synthetic demo data."),
            *(ou("00-base", name, desc=desc) for name, desc in BRANCHES),
            ou("00-base", "declared", f"ou=config,{R}", "Desired, environment-neutral DS configuration"),
            ou("00-base", "observed", f"ou=config,{R}", "Read-only snapshots captured from live servers"))
