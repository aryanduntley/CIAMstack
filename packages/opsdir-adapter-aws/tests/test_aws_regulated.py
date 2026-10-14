"""Regulated data on AWS (5.7b i): export-controlled data (ITAR, EAR) only in AWS GovCloud (US), with the GovCloud
guide's metadata caveats; CJIS and IRS 1075 in GovCloud and the US regions; PHI on HIPAA-eligible services under the
BAA."""
from types import SimpleNamespace

from opsdir.core.directory import make_entry
from opsdir_adapter_aws.boundary import GOVCLOUD_CAVEATS, regulated_verdicts


def _m(data, region):
    env = make_entry("env=prod,cloud=x", ("top", "ciamEnvironment", "ciamEnvironmentPlacement"),
                     {"env": ("prod",), "ciamRegulatedData": tuple(data)})
    return SimpleNamespace(env=env, cloud=make_entry("cloud=x", ("top", "ciamCloud"), {"ciamRegion": (region,)}),
                           label="x/prod", d=None)


def test_export_controlled_data_needs_govcloud():
    assert regulated_verdicts(_m(("itar", "ear"), "us-gov-west-1")) == (("itar", "action", GOVCLOUD_CAVEATS),
                                                                        ("ear", "action", GOVCLOUD_CAVEATS))
    assert regulated_verdicts(_m(("itar",), "us-east-1")) == (("itar", "blocker", (
        "AWS holds export-controlled data only in AWS GovCloud (US) and us-east-1 is a commercial region: move it to "
        "GovCloud.")),)


def test_cjis_and_fti_stay_in_the_us_and_phi_on_eligible_services():
    assert regulated_verdicts(_m(("cjis", "irs-1075"), "us-east-1")) == ()
    assert [v[:2] for v in regulated_verdicts(_m(("cjis", "hipaa"), "eu-west-1"))] == [("cjis", "blocker"),
                                                                                         ("hipaa", "action")]
