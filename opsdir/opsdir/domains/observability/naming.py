"""Observability domain vocabulary: where alert rules, log routes and synthetic checks live; what a control-plane audit
trail covers."""
from ...core.naming import branch
from .attack_table import RETIRED_TACTICS, TACTICS

ALERT_RULES = branch("alert-rules")
LOG_ROUTES = branch("log-routes")
CANARIES = branch("canaries")
COMPARISONS = ("gt", "ge", "lt", "le", "eq", "ne")
LOG_KINDS = ("access", "audit", "error", "admin", "debug", "replication", "transaction", "other")
CANARY_FLOWS = ("login-page", "oidc-token", "saml-sso", "ldap-bind", "health", "other")
CHANNEL_KINDS = ("topic", "action-group", "paging-service", "email", "webhook", "ticket", "other")
DESTINATION_KINDS = ("log-group", "workspace", "siem-index", "bucket", "other")
# MITRE ATT&CK Enterprise tactics by their short names: the current version's (attack_table, ATT&CK v20), in the
# matrix's order, then those it retired, which records and imports may still hold (attack.check_attack flags them)
ATTACK_TACTICS = (*TACTICS, *RETIRED_TACTICS)
# What a rows detection's results name: entity type -> the identifiers it may be named by (ciamEntityMapping)
ENTITY_IDENTIFIERS = {"account": ("name", "upn-suffix", "nt-domain", "sid", "object-id"), "ip": ("address",),
                      "host": ("hostname", "dns-domain"), "url": ("url",), "application": ("app-id", "name")}
ENTITY_MAPPING = (r"^(" + "|".join(ENTITY_IDENTIFIERS) + r") [a-z-]+=[A-Za-z_][A-Za-z0-9_]*$")
DURATION = "^[0-9]+(s|m|h|d)$"                  # 30s, 5m, 1h, 7d
# Product-declared detections (core.contract.ProductDetection; milestone 109, task 594): the canonical fields a
# detection selects, groups and counts on, whatever a product's log calls them (each declaration maps them per product
# version): subject (the account a credential was tried for), source-ip (the client's address), realm (the realm,
# tenant or instance), outcome (success | failure), action (what was done), actor (who changed something), object
# (what was changed)
DETECTION_FIELDS = ("subject", "source-ip", "realm", "outcome", "action", "actor", "object")
DETECTION_OUTCOMES = ("success", "failure")
# login: an end user's sign-in (a credential checked: a journey, an adapter, an LDAP bind); admin-login: an
# administrator's; config-change: a configuration change; key-change: a change to signing or encryption keys or
# certificates
DETECTION_ACTIONS = ("login", "admin-login", "config-change", "key-change")
WINDOW_KINDS = ("sliding", "fixed")             # any span of the window's length | clock-aligned buckets
VALIDATIONS = ("documented", "lab-verified", "live-verified")
# A canonical selector value: <field>=<value>[|<value>...] (every field of a rule's selector matches one of its values)
SELECTOR_TERM = (r"^(" + "|".join(DETECTION_FIELDS) + r")=[A-Za-z0-9_.:@/-]+(\|[A-Za-z0-9_.:@/-]+)*$")
DECLARED_DETECTION = r"^[a-z0-9][a-z0-9-]*:[a-z0-9][a-z0-9.-]*$"     # <adapter>:<detection id>
SEVERITIES = ("sev1", "sev2", "sev3", "sev4")   # ciamSeverity's values (governance), most severe first
AUDIT_SCOPES = ("account", "organization")     # one account (subscription, project), or every account of the
                                               # organization
AUDIT_EVENTS = ("control-plane", "data-read", "data-write")   # management API calls; reads and writes of data
AUDIT_ROLE = "audit-trail"                      # the binding role of an audit trail a cloud reports without one
