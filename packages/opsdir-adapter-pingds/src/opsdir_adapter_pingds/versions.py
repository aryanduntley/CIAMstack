"""What changes between PingDS releases (contract.VersionChange; milestone 86), from the vendor's release notes
(research 2404). The supported range starts at 7.2, so 7.2's renamed setup options (--deploymentId) are never
crossed. None of these changes touches what the record holds about a directory: each is named whenever a move crosses
it. Data."""
from opsdir.core.contract import VersionChange

VERSION_CHANGES = (
    VersionChange(">=7.3", "replication messages move from logs/replication to logs/errors", "log collection",
                  "info", "The log sources follow the target's version; move outside log readers too."),
    VersionChange(">=8.0", "the Prometheus endpoint (/metrics/prometheus/0.0.4) is published by default", "metrics",
                  "info", "Scrapes need no extra configuration on the target; restrict who reaches it."),
    VersionChange(">=8.1", "rotated access and audit log files are named with UTC timestamps ending in Z",
                  "log rotation and retention", "info", "Update scripts and readers that match the old file names."),
    VersionChange(">=8.1", "OPENDJ_JFR_ENABLED is renamed DS_JFR_ENABLED", "the servers' environment", "info",
                  "Rename the variable where images or hosts set it."),
    VersionChange(">=8.1", "backendstat's output is simplified", "runbooks and scripts that read it", "info",
                  "Check runbooks that parse backendstat."),
)
