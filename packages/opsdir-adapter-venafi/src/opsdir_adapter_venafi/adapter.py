"""The venafi adapter's declaration (kind pki, declaration-only): CyberArk Certificate Manager read as a certificate
manager's inventory: Self-Hosted's (Venafi TPP) policy folders (importer venafi/certificates, certificates.py) by a
GET-only collector per collection source (collect.py), and SaaS tenants (importer venafi/saas, saas.py) by a collector
whose only POST is the read-only certificate search (saas_collect.py). It renders nothing."""
from opsdir.core.contract import Adapter
from .certificates import CERTIFICATES_IMPORTER
from .collect import COLLECTORS
from .saas import SAAS_IMPORTER
from .saas_collect import SAAS_COLLECTORS

ADAPTER = Adapter(name="venafi", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(), importers=(CERTIFICATES_IMPORTER,
                                                                                         SAAS_IMPORTER),
                  profile_terms=None, access=None, collectors=(*COLLECTORS, *SAAS_COLLECTORS))
