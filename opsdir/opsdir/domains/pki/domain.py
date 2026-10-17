"""PKI domain: keys, secrets and certificates as metadata and references (never material): credentials, where each
environment keeps them, certificates as public facts, and who uses them; the certification authorities they come
from, the templates those issue from (and the risk of what they let requesters do), what each CA's inventory
says it issued, what its revocation endpoints answered when observed, and what certificate managers hold; the trust
bundles outside PKIs publish and the trust policies the platform accepts certificates under."""
from pathlib import Path

from ...core.contract import Domain, ImportKind, directory_report, sql_report
from .checks import check_certificates, check_credentials
from .issued import AUTHORITY_HEADERS, ISSUED_HEADERS, authority_rows, check_issued_certificates, issued_rows
from .managed import MANAGED_HEADERS, check_managed_certificates, managed_rows
from .pem import check_certificate_pems
from .reports import IMPACT_HEADERS, SPRAWL_HEADERS, rotation_impact_rows, sprawl_rows
from .revocation import REVOCATION_HEADERS, check_revocation_endpoints, revocation_rows
from .schema import FRAGMENT
from .settings import SETTINGS
from .templates import check_template_risk
from .trust import BUNDLE_HEADERS, POLICY_HEADERS, bundle_rows, check_trust, policy_rows

EXPIRING_SQL = ("select cert, purpose, not_after, days_left, array_to_string(names, ','),"
                " (select string_agg(split_part(split_part(u, ',', 1), '=', 2), ',') from unnest(used_by) u)"
                " from v_certificates order by not_after, cert")
EXPIRING_HEADERS = ("certificate", "purpose", "not_after", "days_left", "names", "used_by")

DOMAIN = Domain(name="pki", schema=FRAGMENT, required_roles=(), sql=(Path(__file__).parent / "sql" / "pki.sql",),
                reports={"expiring": sql_report(EXPIRING_HEADERS, EXPIRING_SQL),
                         "credentials": directory_report(SPRAWL_HEADERS, sprawl_rows),
                         "rotation-impact": directory_report(IMPACT_HEADERS, rotation_impact_rows, needs_dn=True),
                         "certificate-authorities": directory_report(AUTHORITY_HEADERS, authority_rows),
                         "issued-certificates": directory_report(ISSUED_HEADERS, issued_rows, dated=True),
                         "revocation-endpoints": directory_report(REVOCATION_HEADERS, revocation_rows, dated=True),
                         "managed-certificates": directory_report(MANAGED_HEADERS, managed_rows, dated=True),
                         "trust-bundles": directory_report(BUNDLE_HEADERS, bundle_rows),
                         "trust-policies": directory_report(POLICY_HEADERS, policy_rows)},
                checks=(check_certificates, check_certificate_pems, check_credentials, check_issued_certificates,
                        check_template_risk, check_revocation_endpoints, check_managed_certificates, check_trust),
                order=40,
                vocabulary={},
                import_kinds=(ImportKind("secret", "ciamSecretRef", ("ciamRefUri",), match="ciamRefUri"),
                              ImportKind("key", "ciamKeyRef", ("ciamRefUri",), match="ciamRefUri")),
                role_links={"ciamEncryptedByRole": "key"}, settings=SETTINGS)
