"""What an adapter's descriptor of a cloud-managed service (contract ManagedService, ManagedDirectory) says of a
capability or of the service existing in a partition: documented supported, documented unsupported, or not
established by the vendor's documentation. Shared by the managed identity and managed directory checks. Pure."""

SUPPORTED, UNSUPPORTED, UNESTABLISHED = "supported", "unsupported", "not established"


def status(spec, partition, capability):
    """(status, source) of a capability on a managed service in a partition: unsupported where the partition or the
    service is documented to lack it, not established where the partition's documentation leaves open what is
    documented elsewhere (a ManagedDirectory's partition_unestablished: the why as the source), supported where
    documented, else not established (None)."""
    lacking = spec.partition_unsupported.get(partition, {})
    if capability in lacking:
        return UNSUPPORTED, lacking[capability]
    open_there = getattr(spec, "partition_unestablished", {}).get(partition, {})
    if capability in open_there:
        return UNESTABLISHED, open_there[capability]
    if capability in spec.unsupported:
        return UNSUPPORTED, spec.unsupported[capability]
    if capability in spec.supported:
        return SUPPORTED, spec.supported[capability]
    return UNESTABLISHED, None


def availability(spec, partition):
    """(status, source) of a managed service existing in a partition."""
    if partition in spec.absent:
        return UNSUPPORTED, spec.absent[partition]
    if partition in spec.available:
        return SUPPORTED, spec.available[partition]
    return UNESTABLISHED, None
