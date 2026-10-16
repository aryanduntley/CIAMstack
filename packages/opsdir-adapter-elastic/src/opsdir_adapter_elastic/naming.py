"""Elastic names: which log destinations are Elastic Security data streams this add-on keeps, the names of what it
renders for one (its index lifecycle policy, the component template attaching it, its snapshot policy), the search
languages of Elastic's detection rules, the offerings of Elastic its stack component can declare (ciamOffering), the
names of the Fleet policies it renders, and the estate settings naming the Kibana space the rules live in and the
integration package versions the Fleet policies use. Pure.

A log destination of kind siem-index whose provider reference is a logs data stream named as Elastic names them
(logs-<dataset>-<namespace>: dataset and namespace lowercase letters, digits, dots and underscores, neither starting
with a dot or an underscore, each at most 100 characters) is an Elastic data stream; a Splunk index name or a Log
Analytics workspace ID is another SIEM's. One the environment inherits from its base (an overlay) is the base's to
render.
"""
import re

from opsdir.core.contract import Setting
from opsdir.core.directory import one
from opsdir.core.environment import offering
from opsdir.domains.observability.realized import keeper_of
from opsdir.domains.observability.siem import is_siem, siem_destinations

_PART = r"[a-z0-9][a-z0-9._]{0,99}"
_STREAM = re.compile(rf"^(?P<type>logs)-(?P<dataset>{_PART})-(?P<namespace>{_PART})$")
POLICY_PREFIX = "opsdir-"           # the ILM and SLM policies the render names after their stream
NATIVE = "esql"                     # ciamSearchLanguage of an ES|QL search: the language its rules are rendered in
# the languages Elastic's detection rules search in (ciamSearchLanguage): ES|QL, KQL (kuery), Lucene, EQL
LANGUAGES = (NATIVE, "kuery", "lucene", "eql")

ADAPTER_NAME = "elastic"
# the offerings of Elastic a stack component of this adapter can declare (ciamOffering): stateful, its default, for
# self-managed Elasticsearch, ECE, ECK and Elastic Cloud Hosted (index lifecycle and snapshot policies), and Elastic
# Cloud Serverless (the data stream lifecycle only, no snapshots)
STATEFUL, SERVERLESS = "stateful", "serverless"
OFFERINGS = (STATEFUL, SERVERLESS)

KIBANA_SPACE = Setting("elastic-kibana-space", "string", "default",
                       "The Kibana space Elastic Security's detection rules live in: opsdir renders them there and "
                       "reads them from there (default: Kibana's default space)")
FILESTREAM_VERSION = Setting("elastic-filestream-version", "string", "2.5.1",
                             "The version of Elastic's Custom Logs (Filestream) integration package (filestream) the "
                             "Fleet policies shipping log files use (default: the current release, which needs Kibana "
                             "9.4 or later; 1.2.0 is the latest for Kibana 8.19)")
KUBERNETES_VERSION = Setting("elastic-kubernetes-version", "string", "1.85.5",
                             "The version of Elastic's Kubernetes integration package (kubernetes) the Fleet policies "
                             "shipping container output use (default: the current release, which needs Kibana 9.5 or "
                             "later; 1.83.1 is the latest for Kibana 8.19)")
SETTINGS = (KIBANA_SPACE, FILESTREAM_VERSION, KUBERNETES_VERSION)


def stream_name(b):
    """The data stream a log destination names (its ciamProviderRef), or None when it isn't a SIEM index or its
    reference isn't a logs data stream name."""
    ref = one(b, "ciamProviderRef") if is_siem(b) else None
    return ref if ref and is_stream(ref) else None


def is_stream(name):
    """Whether name is a logs data stream name as Elastic names them (logs-<dataset>-<namespace>)."""
    return bool(_STREAM.match(name or ""))


def stream_parts(name):
    """(type, dataset, namespace) of a data stream name (logs-<dataset>-<namespace>)."""
    found = _STREAM.match(name)
    return found.group("type"), found.group("dataset"), found.group("namespace")


def dataset_of(name):
    """A data stream's type and dataset (logs-<dataset>), what its component template hook is named by."""
    found = _STREAM.match(name)
    return f"{found.group('type')}-{found.group('dataset')}"


def custom_template(name):
    """The component template a data stream's integration template composes for its dataset's own settings
    (<type>-<dataset>@custom): where the render attaches the stream's index lifecycle policy."""
    return f"{dataset_of(name)}@custom"


def policy_name(name):
    """The ILM (and SLM) policy the render names after a data stream: opsdir-<stream>."""
    return POLICY_PREFIX + name


def serverless(m):
    """Whether environment m's stack declares its Elastic component Elastic Cloud Serverless (ciamOffering)."""
    return offering(m, ADAPTER_NAME, STATEFUL) == SERVERLESS


def fleet_name(m, *parts):
    """The name (and ID) of a Fleet policy the render writes for environment m: opsdir-<cloud>-<env>-<part>-..., each
    part lowercased with runs of other characters than letters and digits made a dash."""
    return "-".join(("opsdir", *(re.sub(r"[^a-z0-9]+", "-", p.lower()).strip("-") for p in (m.label, *parts))))


def keeps(m, b):
    """Adapter siem_indexes: whether log destination b of environment m is an Elastic data stream (stream_name)."""
    return stream_name(b) is not None


def kept_streams(m):
    """Environment m's Elastic data streams its render writes: those it doesn't inherit from a base environment."""
    return tuple(b for b in siem_destinations(m) if stream_name(b) is not None and keeper_of(m, b) is None)
