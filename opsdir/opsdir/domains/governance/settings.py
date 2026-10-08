"""The estate settings the governance domain declares (core.settings): which kinds of configuration sources `opsdir
collect` may read, each off until an approved change turns it on (user decision: read them all, given permission)."""
from ...core.contract import Setting

COLLECT_GIT = Setting("collect-from-git", "bool", False,
                      "Whether opsdir collect may read collection sources in Git repositories (a read-only shallow "
                      "clone with the operator's own Git credentials)")
COLLECT_KUBERNETES = Setting("collect-from-kubernetes", "bool", False,
                             "Whether opsdir collect may read collection sources in Kubernetes (ConfigMaps, with the "
                             "operator's own kubectl context; never Secrets)")
COLLECT_SSH = Setting("collect-from-ssh", "bool", False,
                      "Whether opsdir collect may read collection sources over SSH (fixed read-only commands on the "
                      "declared paths, with the operator's own SSH agent and known hosts)")
SETTINGS = (COLLECT_GIT, COLLECT_KUBERNETES, COLLECT_SSH)
