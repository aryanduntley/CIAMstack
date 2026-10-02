"""Messaging domain: what the platform depends on outside itself and what it tells others. External services (SMTP
relays and email APIs, SMS and voice providers, MFA vendors, CAPTCHA) with the names they allow and the credentials
they need, the addresses it sends mail from and the sending identities that deliver it, and the identity event streams
it publishes. Vendor-neutral: product and cloud adapters read their own configuration into these entries."""
from ...core.contract import Domain, directory_report
from .schema import FRAGMENT
from .services import SENDER_HEADERS, SERVICE_HEADERS, check_services, sender_rows, service_rows
from .streams import STREAM_HEADERS, check_streams, stream_rows

DOMAIN = Domain(name="messaging", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"external-services": directory_report(SERVICE_HEADERS, service_rows),
                         "mail-senders": directory_report(SENDER_HEADERS, sender_rows),
                         "event-streams": directory_report(STREAM_HEADERS, stream_rows)},
                checks=(check_services, check_streams), order=59, vocabulary={})
