"""The x509 adapter's declaration (kind pki, declaration-only): importers x509/revocation (with its estate collector)
and x509/certificates."""
from opsdir.core.contract import Adapter
from .collect import COLLECTORS
from .record import CERTIFICATES_IMPORTER
from .revocation import REVOCATION_IMPORTER

ADAPTER = Adapter(name="x509", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(REVOCATION_IMPORTER, CERTIFICATES_IMPORTER), profile_terms=None, access=None,
                  collectors=COLLECTORS)
