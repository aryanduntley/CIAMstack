"""AD CS adapter: Microsoft Active Directory Certificate Services read into the record's PKI (the core pki domain's
certification authorities, certificate templates, revocation endpoints and issued-certificate inventories), metadata
only. Declaration-only: it renders nothing; its importer reads what the shipped exporter wrote on each CA host and the
forest's certificate templates (inventory.py, templates.py)."""
from opsdir.core.contract import Adapter
from .inventory import INVENTORY_IMPORTER

ADAPTER = Adapter(name="adcs", kind="pki", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(), importers=(INVENTORY_IMPORTER,),
                  profile_terms=None, access=None)
