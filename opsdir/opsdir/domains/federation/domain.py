"""Federation domain: vendor-neutral SAML/OIDC integrations (SP connections, OIDC clients, partner IdPs) and
the claim mappings they release. Product adapters render and import it."""
from ...core.contract import Domain, ImportKind, directory_report
from .checks import check_identity_services
from .managed import MANAGED_HEADERS, managed_rows
from .schema import FRAGMENT
from .served import check_served_integrations

DOMAIN = Domain(name="federation", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"managed-identity": directory_report(MANAGED_HEADERS, managed_rows)},
                checks=(check_identity_services, check_served_integrations), order=30, vocabulary={},
                import_kinds=(ImportKind("managed-identity", "ciamManagedIdentity", ("ciamManagedService",)),))
