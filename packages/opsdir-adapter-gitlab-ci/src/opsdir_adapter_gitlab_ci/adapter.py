"""GitLab CI/CD delivery adapter: the platform's pipelines as GitLab defines them. Declaration-only (an environment
names it in its stack); its importer reads projects' .gitlab-ci.yml and schedules as pipeline jobs."""
from opsdir.core.contract import Adapter
from .pipelines import PIPELINES_IMPORTER

ADAPTER = Adapter(name="gitlab-ci", kind="delivery", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(PIPELINES_IMPORTER,), profile_terms=None, access=None)
