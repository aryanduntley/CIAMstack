"""Automation domain: the platform's hidden automation (cron entries, timers, scheduled tasks, serverless functions,
pipelines) as jobs: what runs, when, on what, with which secrets and code, and who owns it. Vendor-neutral: hosts' and
clouds' adapters and CI systems' packages read their own definitions into these entries."""
from ...core.contract import Domain, ImportKind, directory_report
from .jobs import JOBS_HEADERS, check_jobs, job_rows
from .schema import FRAGMENT

DOMAIN = Domain(name="automation", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"jobs": directory_report(JOBS_HEADERS, job_rows)},
                checks=(check_jobs,), order=57, vocabulary={},
                import_kinds=(ImportKind("job", "ciamJobBinding"),))
