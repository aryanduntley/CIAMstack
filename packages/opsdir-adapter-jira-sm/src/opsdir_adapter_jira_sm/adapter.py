"""Jira Service Management adapter: an IT service management system whose change tickets the record's change records
are tracked by; it renders nothing. Its importer reads the linked tickets and their approval steps as evidence
(changes.py) through the operator's mapping of the site's statuses and change fields (mapping.py), from an export or,
read-only, from the site's REST APIs (collect.py); the governance domain compares them with the record
(domains.governance.tickets). Never an approval opsdir acts on, never a write to the site."""
from opsdir.core.contract import Adapter
from .changes import CHANGES_IMPORTER
from .collect import COLLECTORS
from .mapping import CHANGE_FIELDS, STATUS_STATES

ADAPTER = Adapter(name="jira-sm", kind="itsm", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(CHANGES_IMPORTER,), profile_terms=None, access=None, collectors=COLLECTORS,
                  settings=(STATUS_STATES, CHANGE_FIELDS))
