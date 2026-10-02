"""Azure DevOps delivery adapter: the platform's pipelines as Azure Pipelines defines them. Declaration-only (an
environment names it in its stack); its importer reads repositories' YAML pipelines as pipeline jobs."""
from opsdir.core.contract import Adapter
from .pipelines import PIPELINES_IMPORTER

ADAPTER = Adapter(name="azure-devops", kind="delivery", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(PIPELINES_IMPORTER,))
