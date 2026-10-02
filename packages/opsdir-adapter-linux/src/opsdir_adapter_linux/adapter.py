"""Linux host adapter: what runs on the platform's Linux servers beyond its products. Declaration-only (an environment
names it in its stack; it renders nothing yet): its importers read the servers' own files, their crontabs and systemd
timers as jobs (linux/jobs) and what they run beyond the product as host baselines (linux/baseline)."""
from opsdir.core.contract import Adapter
from .baseline import BASELINE_IMPORTER
from .jobs import JOBS_IMPORTER

ADAPTER = Adapter(name="linux", kind="host", applies=None, required_roles=(), render_neutral=None, render_env=None,
                  checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None, vocabulary={},
                  schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(JOBS_IMPORTER, BASELINE_IMPORTER), profile_terms=None)
