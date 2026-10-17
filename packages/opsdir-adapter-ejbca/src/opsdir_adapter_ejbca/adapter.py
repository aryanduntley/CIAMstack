"""The EJBCA adapter's declaration (kind pki, declaration-only): importer ejbca/inventory and its collector."""
from opsdir.core.contract import Adapter
from .collect import COLLECTORS
from .inventory import INVENTORY_IMPORTER

ADAPTER = Adapter(name="ejbca", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(), importers=(INVENTORY_IMPORTER,),
                  profile_terms=None, access=None, collectors=COLLECTORS)
