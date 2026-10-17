"""The venafi adapter's declaration (kind pki, declaration-only): Venafi / CyberArk Certificate Manager – Self-Hosted's
policy folders read as a certificate manager's inventory (importer venafi/certificates, certificates.py) by a GET-only
collector per collection source (collect.py). It renders nothing."""
from opsdir.core.contract import Adapter
from .certificates import CERTIFICATES_IMPORTER
from .collect import COLLECTORS

ADAPTER = Adapter(name="venafi", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(), importers=(CERTIFICATES_IMPORTER,),
                  profile_terms=None, access=None, collectors=COLLECTORS)
