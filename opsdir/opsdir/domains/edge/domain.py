"""Edge domain: how traffic reaches the platform and what protects it. Traffic and protection policies (TLS handling
and level, health checks, stickiness, firewall rules, rate limits, DDoS protection, a CDN) and header contracts are
intent; the DNS zones, records and forwarders, and the firewalls, CDNs, DDoS protection, gateways and proxies in front
of the service names are bindings, read in by the cloud importers and rendered by the cloud adapters. Vendor-neutral:
products declare their endpoints (contract.Endpoint)."""
from ...core.contract import Domain, directory_report
from .dns import DNS_HEADERS, check_dns, dns_rows
from .headers import HEADER_HEADERS, check_headers, header_rows
from .imports import IMPORT_KINDS, ROLE_LINKS
from .policies import POLICY_HEADERS, check_policies, policy_rows
from .running import EDGE_SERVICE_HEADERS, check_running, edge_service_rows
from .schema import FRAGMENT

DOMAIN = Domain(name="edge", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"edge-policies": directory_report(POLICY_HEADERS, policy_rows),
                         "edge-services": directory_report(EDGE_SERVICE_HEADERS, edge_service_rows),
                         "dns": directory_report(DNS_HEADERS, dns_rows),
                         "header-contracts": directory_report(HEADER_HEADERS, header_rows)},
                checks=(check_policies, check_running, check_headers, check_dns), order=64, vocabulary={},
                import_kinds=IMPORT_KINDS, role_links=ROLE_LINKS)
