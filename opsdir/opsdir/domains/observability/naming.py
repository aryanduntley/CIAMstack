"""Observability domain vocabulary: where alert rules, log routes and synthetic checks live."""
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
