"""BMC Helix ITSM / Remedy adapter: an IT service management system whose change tickets the record's change records
are tracked by; it renders nothing. Its importer reads the linked change tickets and their approval signatures as
evidence (changes.py), their statuses through the estate setting bmc-helix-status-states (states.py), from saved AR
System REST answers or, read-only, from the AR System REST API (collect.py); the governance domain compares them with
the record (domains.governance.tickets). It drafts the work orders findings are handed to their owning teams by, as
files a person posts (drafts.py, settings bmc-helix-ticket-groups and bmc-helix-ticket-fields), and reads the linked
work orders back as work tickets (workorders.py, bmc-helix-work-order-states). Never an approval opsdir acts on,
never a write to BMC."""
from opsdir.core.contract import Adapter
from .changes import CHANGES_IMPORTER
from .collect import COLLECTORS
from .drafts import FIELD_LIMITS, TICKET_FIELDS, TICKET_GROUPS, ticket_draft
from .states import STATUS_STATES, WORK_ORDER_STATES

ADAPTER = Adapter(name="bmc-helix", kind="itsm", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(CHANGES_IMPORTER,), profile_terms=None, access=None, collectors=COLLECTORS,
                  settings=(STATUS_STATES, WORK_ORDER_STATES, TICKET_GROUPS, TICKET_FIELDS, FIELD_LIMITS),
                  ticket_draft=ticket_draft)
