"""The DoD PKI adapter's declaration (kind pki, declaration-only): importer dod-pki/bundle."""
from opsdir.core.contract import Adapter
from .bundle import BUNDLE_IMPORTER

ADAPTER = Adapter(name="dod-pki", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(), importers=(BUNDLE_IMPORTER,),
                  profile_terms=None, access=None, collectors=())
