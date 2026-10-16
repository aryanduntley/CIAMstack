"""What changes between PingAccess releases (contract.VersionChange; decision 2375), as dated data: only what Ping's
release notes and installation requirements state (research note 3076, Ping's PingAccess 8.2 and 9.1 documentation,
read 2026-10-15), so the planner names it when a move upgrades PingAccess. Pure.

  8.2.1 (April 2025)   FIPS mode uses Bouncy Castle FIPS 2.0 (FIPS 140-3); in FIPS mode key pairs are PEM only
  9.1 (June 2026)      a temporary port, 9095, is used while the cluster's certificates are rotated
"""
from opsdir.core.contract import VersionChange
from opsdir.core.directory import children, rdn_value
from .naming import SERVER_ROLES, held_base


def key_pairs(d, m, role):
    """A VersionChange.touches: the key pairs the record holds (environment-bound, recreated per environment)."""
    return tuple(rdn_value(k) for k in children(d, held_base("keyPairs"), "paHeld")) if role in SERVER_ROLES else ()


VERSION_CHANGES = (
    VersionChange(">=8.2.1", "FIPS mode uses the Bouncy Castle FIPS 2.0 provider (FIPS 140-3), and key pairs in FIPS "
                  "mode are PEM only (no PKCS#12)", "key pairs on nodes running in FIPS mode", "info",
                  "Where the target runs FIPS mode, recreate PKCS#12 key pairs as PEM.", key_pairs),
    VersionChange(">=9.1", "rotating the cluster's certificates uses a temporary port, 9095, between the admin node "
                  "and the engines", "the admin node's and engines' firewall rules", "action",
                  "Open 9095 from the engines to the admin node before a certificate rotation (the ports matrix "
                  "lists it for 9.1 and later)."),
)
