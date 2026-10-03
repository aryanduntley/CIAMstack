"""GitHub Actions delivery adapter: the platform's pipelines as GitHub Actions defines them. Declaration-only (an
environment names it in its stack); its importer reads repositories' workflows as pipeline jobs."""
from opsdir.core.contract import Adapter
from .workflows import WORKFLOWS_IMPORTER

ADAPTER = Adapter(name="github-actions", kind="delivery", applies=None, required_roles=(), render_neutral=None,
                  render_env=None, checks=(), ref_schemes=(), secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(), products=(), secret_patterns=(),
                  importers=(WORKFLOWS_IMPORTER,), profile_terms=None, access=None)
