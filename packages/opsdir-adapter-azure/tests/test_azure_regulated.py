"""Regulated data on Azure (5.7b i): Azure and Azure Government alike per Microsoft; in commercial Azure export-
controlled data and CJIS ride on the customer's end-to-end encryption, Azure Government the better fit (an action,
decision 2807); IRS 1075's contractual amendment and HIPAA's BAA in either."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir_adapter_azure.boundary import COMMERCIAL, regulated_verdicts


def _m(data, region):
    env = make_entry("env=prod,cloud=x", ("top", "ciamEnvironment", "ciamEnvironmentPlacement"),
                     {"env": ("prod",), "ciamRegulatedData": tuple(data)})
    return SimpleNamespace(env=env, cloud=make_entry("cloud=x", ("top", "ciamCloud"), {"ciamRegion": (region,)}),
                           label="x/prod", d=None)


def test_commercial_azure_holds_export_controlled_and_cji_behind_the_customer_s_encryption():
    assert regulated_verdicts(_m(("itar", "cjis"), "eastus2")) == (("itar", "action", COMMERCIAL),
                                                                   ("cjis", "action", COMMERCIAL))
    assert regulated_verdicts(_m(("itar", "ear", "cjis"), "usgovvirginia")) == ()


def test_fti_and_phi_name_what_microsoft_signs():
    assert [v[0] for v in regulated_verdicts(_m(("hipaa", "irs-1075"), "usgovarizona"))] == ["hipaa", "irs-1075"]
    assert all(v[1] == "action" for v in regulated_verdicts(_m(("hipaa", "irs-1075"), "eastus2")))
