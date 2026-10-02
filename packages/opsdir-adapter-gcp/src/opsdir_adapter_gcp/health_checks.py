"""Google Cloud's health-check probe sources for passthrough network load balancers (docs.cloud.google.com,
load-balancing/docs/health-check-concepts). A firewall rule admitting them belongs to a load balancer, not to the
record's firewall rules: the renderer adds one per service and the importers leave them out."""

_PROBES = {"INTERNAL": ("35.191.0.0/16",),
           "EXTERNAL": ("35.191.0.0/16", "209.85.152.0/22", "209.85.204.0/22")}


def probe_ranges(scheme):
    """The probe source ranges for a load balancing scheme (INTERNAL or EXTERNAL, backend-service based)."""
    return _PROBES[scheme]


def is_probe_rule(source_ranges):
    """Whether a rule's sources are all probe ranges."""
    sources = set(source_ranges or ())
    return bool(sources) and sources <= {r for ranges in _PROBES.values() for r in ranges}
