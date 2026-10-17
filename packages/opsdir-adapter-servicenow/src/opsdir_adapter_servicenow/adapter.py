"""ServiceNow adapter: an IT service management system whose change tickets the record's change records are tracked by;
it renders nothing. Its importer reads the linked tickets and their approval records as evidence (changes.py), from
an export or, read-only, from the instance's Table API (collect.py); the governance domain compares them with the
record (domains.governance.tickets). Never an approval opsdir acts on, never a write to the instance."""
from opsdir.core.contract import Adapter
from .changes import CHANGES_IMPORTER, SETTINGS
from .collect import COLLECTORS

ADAPTER = Adapter(name="servicenow", kind="itsm", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(CHANGES_IMPORTER,), profile_terms=None, access=None, collectors=COLLECTORS,
                  settings=SETTINGS)
