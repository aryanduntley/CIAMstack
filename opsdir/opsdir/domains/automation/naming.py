"""Automation domain vocabulary: where jobs live."""
from ...core.naming import branch

JOBS = branch("jobs")
KINDS = ("cron", "timer", "scheduled-task", "function", "pipeline", "other")
ON_SERVERS = ("cron", "timer", "scheduled-task")      # kinds that run on servers of a role
REALIZED = ("function",)          # kinds each environment realizes as a binding (a pipeline runs in its CI system; an
                                  # environment binds one only when its CI is per environment, e.g. CodePipeline)


def job_dn(name):
    return f"cn={name},{JOBS}"
