"""The estate settings the governance domain declares (core.settings): which kinds of configuration sources `opsdir
collect` may read, each off until an approved change turns it on (user decision: read them all, given permission), and
whether the record is a production one (the posture check holds a production record to production rules)."""
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
DEPLOYMENTS = ("development", "production")
DEPLOYMENT = Setting("deployment", "string", "development",
                     "What this record is: development (a lab, the showcase) or production (the company's record of "
                     "its live platform); in production the posture check refuses development defaults",
                     choices=DEPLOYMENTS)
APPROVAL_SEPARATION = Setting("approval-separation", "bool", True,
                              "Whether a change record's approver must be someone other than its author (the store "
                              "enforces it): turn it off only for a one-person install; the posture check warns on a "
                              "development record and fails a production one")
SETTINGS = (COLLECT_GIT, COLLECT_KUBERNETES, COLLECT_SSH, DEPLOYMENT, APPROVAL_SEPARATION)
