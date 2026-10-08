"""FedRAMP compliance adapter: FedRAMP's machine-readable formats read into the record. Declaration-only; its importer
reads cloud offerings' Certification Package Overviews as the authorizations the estate relies on."""
from opsdir.core.contract import Adapter
from .cpo import CPO

ADAPTER = Adapter(name="fedramp", kind="compliance", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(CPO,), profile_terms=None, access=None)
