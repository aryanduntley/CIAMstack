"""Hybrid identity: the organization's own directory a cloud's users come from, as the cloud records it
(ciamCloudAccount: ciamOnPremDirectory, ciamDirectorySync, ciamPasswordWriteback). Sync is per tenant, so it is the
cloud's, shared by its environments. Pure.

The record says which directories (their domains), how their users sign in to the cloud (password-hash, pass-through,
federation; password-hash may sit beside the others) and whether a password changed in the cloud is written back.
Threat detection covering the directory itself is a security service whose coverage includes on-prem-directory; the
adapters say what their cloud needs of each (a sensor product, the sync a risk signal depends on)."""
from ...core.directory import one, values
from .security import security_services

DIRECTORY_AREA = "on-prem-directory"


def on_prem_directories(m):
    """The domains of the on-prem directories environment m's cloud takes its users from, in record order."""
    return values(m.cloud, "ciamOnPremDirectory") if m.cloud is not None else ()


def directory_sync(m):
    """How the users of environment m's on-prem directories sign in to its cloud (ciamDirectorySync), in record
    order."""
    return values(m.cloud, "ciamDirectorySync") if m.cloud is not None else ()


def password_writeback(m):
    """Whether environment m's cloud writes passwords changed in it back to its on-prem directories (None: not
    recorded)."""
    v = one(m.cloud, "ciamPasswordWriteback") if m.cloud is not None else None
    return True if v == "TRUE" else False if v == "FALSE" else None


def directory_watchers(m):
    """Environment m's threat-detection services covering its on-prem directories."""
    return tuple(s for s in security_services(m, "threat-detection")
                 if DIRECTORY_AREA in values(s, "ciamSecurityCoverage"))
