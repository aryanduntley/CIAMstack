"""The estate settings the governance domain declares (core.settings): which kinds of configuration sources `opsdir
collect` may read, each off until an approved change turns it on (user decision: read them all, given permission);
whether the record is a production one (the posture check holds a production record to production rules), whether an
author may approve their own change, how many people approve a change per environment, which login the HTTP API server
connects as, and the record database's recovery targets."""
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
API_LOGIN = Setting("api-login", "string", "",
                    "The database login the HTTP API server connects as, the only one the store trusts to say which "
                    "person a write is for (the person its verified token names); empty: no API login is trusted. "
                    "Changing it is a governed write like any setting")
_TIER = r"\s*(\*|[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*[1-9]\s*"
APPROVALS_REQUIRED = Setting("approvals-required", "string", "",
                             "How many distinct people must approve a change, per environment, as comma-separated "
                             "<cloud/env>=<1-9> with * for every environment not listed (e.g. *=1, collins-aws/prod=2)"
                             "; "
                             "never the author while approval-separation is on. A change stays proposed until its "
                             "records' environments have their approvals, and the store refuses writes under a change "
                             "short of them. Unset: one approver",
                             pattern=f"{_TIER}(,{_TIER})*")
_DURATION = r"[1-9][0-9]*(m|h|d)"
RECOVERY_RPO = Setting("recovery-rpo", "string", "",
                       "The record database's recovery point objective: the most recent writes the company accepts "
                       "losing after a failure or a region loss, as minutes, hours or days (15m, 1h, 1d); the posture "
                       "check reports it and asks for one on a production record",
                       pattern=_DURATION)
RECOVERY_RTO = Setting("recovery-rto", "string", "",
                       "The record database's recovery time objective: how long the record may be unavailable after a "
                       "failure or a region loss before it is back in service, as minutes, hours or days (30m, 4h); "
                       "the posture check reports it and asks for one on a production record",
                       pattern=_DURATION)
SETTINGS = (COLLECT_GIT, COLLECT_KUBERNETES, COLLECT_SSH, DEPLOYMENT, APPROVAL_SEPARATION, APPROVALS_REQUIRED,
            API_LOGIN, RECOVERY_RPO, RECOVERY_RTO)
