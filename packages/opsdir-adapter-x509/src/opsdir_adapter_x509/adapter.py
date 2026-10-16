"""The x509 adapter's declaration (kind pki, declaration-only): importer x509/revocation and its estate collector."""
from opsdir.core.contract import Adapter
from .collect import COLLECTORS
from .revocation import REVOCATION_IMPORTER

ADAPTER = Adapter(name="x509", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(), importers=(REVOCATION_IMPORTER,),
                  profile_terms=None, access=None, collectors=COLLECTORS)
