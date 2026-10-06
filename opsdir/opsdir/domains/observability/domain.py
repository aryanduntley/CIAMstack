"""Observability domain: what the platform is watched for (alert rules on neutral signals, delivered through a
channel each environment binds), where its logs go and how long they must be kept (log routes, kept by a destination
each environment binds), and the synthetic checks that sign in as a user would (canaries); and what each cloud runs of
it (alarms and checks realizing them, read in by cloud importers). Vendor-neutral: cloud adapters read what their
monitoring runs into it, and render it (path 6)."""
from ...core.contract import Domain, ImportKind, directory_report
from .alerts import ALERT_HEADERS, CANARY_HEADERS, alert_rows, canary_rows, check_alerts
from .logs import LOG_HEADERS, check_logs, log_rows
from .realized import MONITOR_HEADERS, check_realized, monitor_rows
from .schema import FRAGMENT

DOMAIN = Domain(name="observability", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"alerts": directory_report(ALERT_HEADERS, alert_rows),
                         "log-routes": directory_report(LOG_HEADERS, log_rows),
                         "canaries": directory_report(CANARY_HEADERS, canary_rows),
                         "monitors": directory_report(MONITOR_HEADERS, monitor_rows)},
                checks=(check_alerts, check_logs, check_realized), order=60, vocabulary={},
                import_kinds=(ImportKind("channel", "ciamAlertChannel", ("ciamChannelKind",)),
                              ImportKind("logs", "ciamLogDestination", ("ciamDestinationKind",)),
                              ImportKind("alarm", "ciamAlarmBinding"), ImportKind("canary", "ciamCanaryBinding")),
                role_links={"ciamLogDestinationRole": "logs"})
