"""Network domain: how the platform's networks carry its traffic beyond networks, subnets and inbound rules. The outside
sites the platform must reach are intent; route tables, network ACLs, private endpoints, endpoint services, the proxy
egress passes, time sources, flow logs and firewall policies are bindings, read in by the cloud importers and rendered
by the cloud adapters (the network's plumbing into the landing zone's root). Vendor-neutral: products declare the
ports they listen on (contract.Listener), from which the connectors derive the ports matrix."""
from ...core.contract import Domain, directory_report
from .checks import (check_egress, check_endpoint_services, check_flow_logs, check_interconnects,
                     check_private_endpoints, check_sites, check_time)
from .reports import (ENDPOINT_SERVICE_HEADERS, PRIVATE_ENDPOINT_HEADERS, ROUTE_HEADERS, SITE_HEADERS,
                      endpoint_service_rows, private_endpoint_rows, route_rows, site_rows)
from .schema import FRAGMENT

DOMAIN = Domain(name="network", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"routes": directory_report(ROUTE_HEADERS, route_rows),
                         "private-endpoints": directory_report(PRIVATE_ENDPOINT_HEADERS, private_endpoint_rows),
                         "endpoint-services": directory_report(ENDPOINT_SERVICE_HEADERS, endpoint_service_rows),
                         "egress-sites": directory_report(SITE_HEADERS, site_rows)},
                checks=(check_egress, check_private_endpoints, check_endpoint_services, check_interconnects,
                        check_sites, check_time, check_flow_logs), order=66, vocabulary={})
