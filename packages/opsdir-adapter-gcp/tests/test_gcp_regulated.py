"""Regulated data on Google Cloud (5.7b i): an Assured Workloads folder of the data's regime (ITAR, CJIS, IRS_1075, the
healthcare package), one regime per folder, the data's taking precedence over a required level's (decision 2807, the
planner naming the level's package it doesn't apply); US locations for ITAR, CJIS and IRS 1075; CMEK for ITAR and CJIS;
no package for EAR."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.account import regime
from opsdir_adapter_gcp.boundary import regulated_verdicts, render_workload


def _m(data=(), levels=(), met=("assured-workload",), region="us-central1"):
    env = make_entry("env=prod,cloud=x", ("top", "ciamEnvironment", "ciamEnvironmentPlacement"),
                     {"env": ("prod",), "ciamRegulatedData": tuple(data), "ciamRequiredAuthorization": tuple(levels),
                      "ciamConfigurationMet": tuple(met)})
    cloud = make_entry("cloud=x", ("top", "ciamCloud", "ciamCloudAccount"),
                       {"ciamRegion": (region,), "ciamOrganizationRef": ("organizations/42",),
                        "ciamBillingAccountRef": ("01A2B3-C4D5E6-F7A8B9",)})
    return SimpleNamespace(env=env, cloud=cloud, label="x/prod", d=None)


def test_the_data_s_regime_takes_the_folder_before_the_level_s():
    assert regime(_m(levels=("dod-il4",))) == "IL4"
    assert regime(_m(("hipaa", "itar"), levels=("dod-il4",))) == "ITAR"
    assert regime(_m(("ear",), levels=("fedramp-moderate",))) == "FEDRAMP_MODERATE"     # no EAR package
    (out,) = as_text(render_workload(_m(("cjis",))))
    assert 'compliance_regime = "CJIS"' in out


def test_verdicts_name_the_folder_the_region_the_keys_and_the_level_not_applied():
    assert regulated_verdicts(_m(("itar",), levels=("fedramp-high",))) == (
        ("itar", "action", "Google requires customer-managed encryption keys (Cloud KMS) for it."),
        ("itar", "action", "x/prod requires fedramp-high and its Assured Workloads folder applies ITAR's package, not "
                           "FEDRAMP_HIGH's: confirm with the authorizing official."))
    blockers = [v[2] for v in regulated_verdicts(_m(("itar", "irs-1075"), met=(), region="europe-west1"))
                if v[1] == "blocker"]
    assert blockers == [
        "Google holds it in an Assured Workloads ITAR folder and x/prod records none (ciamConfigurationMet "
        "assured-workload).",
        "Google offers ITAR in US locations only and europe-west1 isn't one.",
        "Google holds it in an Assured Workloads IRS_1075 folder and x/prod records none (ciamConfigurationMet "
        "assured-workload).",
        "one Assured Workloads folder holds one regime and x/prod's takes ITAR: hold irs-1075 data in an environment "
        "of its own.",
        "Google offers IRS_1075 in US locations only and europe-west1 isn't one."]
    assert [v[1] for v in regulated_verdicts(_m(("ear",)))] == ["action"]
    assert regulated_verdicts(_m(("hipaa",), region="us")) == ()
