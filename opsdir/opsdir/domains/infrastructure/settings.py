"""The estate settings the infrastructure domain declares (core.settings): values the platform's managers may change for
the whole estate, under an approved change."""
from ...core.contract import Setting

UNUSED_RULE_DAYS = Setting("firewall-unused-rule-days", "int", 90,
                           "How long the firewalls must have counted a firewall rule's hits without one before the "
                           "planner asks whether the rule is still needed, in days", minimum=1)
SETTINGS = (UNUSED_RULE_DAYS,)
