"""Infrastructure domain vocabulary: its branches and enumerations."""
from ...core.naming import branch

ENVIRONMENTS = branch("environments")
EXTERNAL_ALLOWLISTS = branch("external-allowlists")
EXPOSURES = ("internal", "internet")    # a service name's load balancer: private network only, or internet-facing
# A firewall rule read back from a firewall manager's running configuration (ciamRunningState): on a manager (Panorama:
# its delivery to the firewalls unconfirmed), on a firewall (on a manager: on every firewall it pushes to), on some of
# the firewalls a manager pushes to, there but switched off, or not there
RUNNING_STATES = ("committed", "deployed", "partial", "disabled", "missing")
# What a manager's managed firewall runs of one rule (a ciamRuleObservation's ciamRunningState)
OBSERVED_STATES = ("deployed", "disabled", "missing")
# What a rule read back runs that its own attributes can't hold (ciamRunningFact '<key> <value>'): what the record owns
# (the next push restores it) and the network team's settings that limit what the rule admits
OWNED_FACTS = ("action", "log-end", "destination", "description", "source", "service")
ACCESS_FACTS = ("negate-source", "negate-destination", "schedule", "rulebase")
RUNNING_FACT = f"^({'|'.join((*OWNED_FACTS, *ACCESS_FACTS))}) [^ ].*$"
ALLOWLIST_REF = r"^[a-z0-9][a-z0-9-]*:[^ ].*$"     # <adapter>:<path in the system it names>
