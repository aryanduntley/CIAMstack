"""Splunk names: which log destinations are Splunk indexes this add-on keeps, the app its configuration ships in, and
the estate setting saying where the Universal Forwarder is installed on the servers. Pure.

A log destination of kind siem-index whose provider reference is a Splunk index name (lowercase letters, digits,
underscores and hyphens, not starting with an underscore or a hyphen: Splunk's rule for index names) is a Splunk
index; a Log Analytics workspace's resource ID, or any other reference, is another SIEM's. One the environment
inherits from its base (an overlay) is the base's to render.
"""
import re

from opsdir.core.contract import Setting
from opsdir.core.directory import one
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.siem import is_siem, siem_destinations

APP = "opsdir_ciam"                                 # the Splunk app holding the indexes and saved searches
APP_DIR = f"splunk/apps/{APP}/default"              # where the render writes it
INDEXES = f"{APP_DIR}/indexes.conf"
SAVED_SEARCHES = f"{APP_DIR}/savedsearches.conf"
_INDEX = re.compile(r"^[a-z0-9][a-z0-9_-]*$")

FORWARDER_HOME = Setting("splunk-forwarder-home", "string", "/opt/splunkforwarder",
                         "Where the Splunk Universal Forwarder is installed on the servers ($SPLUNK_HOME): the "
                         f"forwarder reads the inputs opsdir renders from etc/apps/{APP}/local/inputs.conf under it")
SETTINGS = (FORWARDER_HOME,)


def index_name(b):
    """The Splunk index a log destination names (its ciamProviderRef), or None when it isn't a SIEM index or its
    reference isn't a Splunk index name."""
    ref = one(b, "ciamProviderRef") if is_siem(b) else None
    return ref if ref and _INDEX.match(ref) else None


def keeps(m, b):
    """Adapter siem_indexes: whether log destination b of environment m is a Splunk index (index_name)."""
    return index_name(b) is not None


def kept_indexes(m):
    """Environment m's Splunk indexes its render writes: those it doesn't inherit from a base environment."""
    return tuple(b for b in siem_destinations(m) if index_name(b) is not None and keeper_of(m, b) is None)
