"""Observability domain vocabulary: where alert rules, log routes and synthetic checks live; what a control-plane audit
trail covers."""
from ...core.naming import branch

ALERT_RULES = branch("alert-rules")
LOG_ROUTES = branch("log-routes")
CANARIES = branch("canaries")
COMPARISONS = ("gt", "ge", "lt", "le", "eq", "ne")
LOG_KINDS = ("access", "audit", "error", "admin", "debug", "replication", "transaction", "other")
CANARY_FLOWS = ("login-page", "oidc-token", "saml-sso", "ldap-bind", "health", "other")
CHANNEL_KINDS = ("topic", "action-group", "paging-service", "email", "webhook", "ticket", "other")
DESTINATION_KINDS = ("log-group", "workspace", "siem-index", "bucket", "other")
DURATION = "^[0-9]+(s|m|h|d)$"                  # 30s, 5m, 1h, 7d
AUDIT_SCOPES = ("account", "organization")     # one account (subscription, project), or every account of the organization
AUDIT_EVENTS = ("control-plane", "data-read", "data-write")   # management API calls; reads and writes of data
AUDIT_ROLE = "audit-trail"                      # the binding role of an audit trail a cloud reports without one
