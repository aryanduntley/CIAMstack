"""Google Cloud's rendered Terraform as the state applying it would record (the round trip, 5.5c): ids as the google
provider gives them, a realized binding's provider reference, what Google assigns (a service account's email and name,
a workload identity pool's name), effective labels, and a data source finding what the record holds."""
import json

from opsdir.core.environment import env_model
from opsdir.core.interchange.ldif import parse
from opsdir_adapter_gcp.rendered_state import provider_facts, rendered_states, resource_id
from opsdir_format_terraform.hcl import TfBlock, block, ref
import mini_estate
from support import build_directory

ENV = "env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
ALERT = (f"dn: cn=ds-lag,ou=bindings,{ENV}\nobjectClass: top\nobjectClass: ciamAlarmBinding\ncn: ds-lag\n"
         "ciamBindingRole: alarm-lag\nciamProviderRef: projects/p1/alertPolicies/2001\n")
PROVIDER = (TfBlock("provider", ("google",), (("project", ref("var.project_id")), ("region", "us-central1"),
                                              ("default_labels", {"owner": "ciam"}))),
            TfBlock("variable", ("project_id",), (("default", "p1"),)))


def test_the_provider_gives_project_region_and_default_labels():
    assert provider_facts(PROVIDER) == ("p1", "us-central1", {"owner": "ciam"})


def test_ids_as_the_google_provider_gives_them():
    assert resource_id("google_compute_subnetwork", "s", None, {"name": "ciam-pf"}, "p1", "us-central1") == \
        "projects/p1/regions/us-central1/subnetworks/ciam-pf"
    assert resource_id("google_compute_router_nat", "n", None, {"name": "nat", "router": "r"}, "p1", "us-east1") == \
        "p1/us-east1/r/nat"
    assert resource_id("google_scc_v2_project_notification_config", "c", None,
                       {"config_id": "scc-findings", "location": "global"}, "p1", "us-central1") == \
        "projects/p1/locations/global/notificationConfigs/scc-findings"
    assert "/opsdirSynthetic/" in resource_id("google_something_new", "x", None, {}, "p1", "r")


def test_what_google_assigns_and_what_the_record_holds():
    d = build_directory(mini_estate.REGISTRY, tuple(parse(mini_estate.LDIF + "\n" + ALERT)))
    main = "\n\n".join(block(*b) for b in (
        *PROVIDER, TfBlock("resource", ("google_monitoring_alert_policy", "ds_lag"), (("display_name", "DS lag"),)),
        TfBlock("resource", ("google_service_account", "ci"), (("account_id", "ciam-deploy"),)),
        TfBlock("resource", ("google_iam_workload_identity_pool", "gh"), (("workload_identity_pool_id", "gh"),)),
        TfBlock("resource", ("google_service_account_iam_member", "ci"), (
            ("service_account_id", ref("google_service_account.ci.name")),
            ("member", ref('"principal://iam.googleapis.com/${google_iam_workload_identity_pool.gh.name}/subject/x"')),
            ("labels", {"role": "ci"}))))) + "\n"
    (text,) = rendered_states({"alpha/prod/main.tf": main}, d, "alpha/prod").values()
    found = {r["name"]: r["instances"][0]["attributes"] for r in json.loads(text)["resources"]}
    assert (found["ds_lag"]["id"], found["ds_lag"]["name"]) == ("projects/p1/alertPolicies/2001",) * 2
    assert found["ci"]["service_account_id"] == "projects/p1/serviceAccounts/ciam-deploy@p1.iam.gserviceaccount.com"
    assert found["ci"]["member"].startswith("principal://iam.googleapis.com/projects/") and \
        found["ci"]["member"].endswith("/locations/global/workloadIdentityPools/gh/subject/x")
    assert found["ci"]["effective_labels"] == {"owner": "ciam", "role": "ci"}
