"""On-prem provider adapter: environments on the operators' own hardware (ciamCloudProvider onprem). Its region is the
site it runs in (the organization's sites as the region catalog: onprem/sites); it renders nothing itself (the
configuration-management and product adapters render its servers); its planner check asks the site's teams for what
fronts and connects the servers unless an add-on in the stack renders it."""
from opsdir.core.contract import Adapter
from .keepers import check_keepers
from .sites import PARTITION, PREREQUISITE, PROVIDER, SITES


def applies(m):
    return m.provider == PROVIDER


ADAPTER = Adapter(name="onprem", kind="provider", applies=applies, required_roles=(),
                  render_neutral=None, render_env=None, checks=(check_keepers,), ref_schemes=(),
                  secret_schemes={}, renders=None, neutral_label=None,
                  vocabulary={"ciamCloudProvider": (PROVIDER,), "ciamOnProvider": (PROVIDER,),
                              "ciamCloudEnvironment": (PARTITION,)}, schema=None,
                  formats=(), products=(), secret_patterns=(), importers=(SITES,), profile_terms=None, access=None,
                  prerequisites=(PREREQUISITE,))
