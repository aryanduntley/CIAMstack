"""Data discovery on Google Cloud as Sensitive Data Protection: an inspect template with the own data types as custom
regular-expression info types, a discovery config profiling the examined Cloud Storage buckets (daily, or monthly from
30 days) with Pub/Sub notifications to the findings topic; other stores, BigQuery-only results and someone else's
discovery in comments; another interval as a paused config a daily Workflows workflow resumes once due, except under
DoD IL4/IL5 (an action); read back from state."""
import json

from opsdir.core.interchange.ldif import LdifRecord
from opsdir_format_terraform.hcl import as_text
from opsdir_adapter_gcp.discovery import (RESCAN_WORKFLOW, check_discovery_cadence, discovery_resources, info_type,
                                          render_discovery)
from opsdir_adapter_gcp.rendered_state import rendered_states
from opsdir_format_terraform.hcl import TfBlock, block
from opsdir_format_terraform.state import read_state
from network_fixtures import ALPHA, BETA, context, entry, model

TOPIC = "projects/ea-ciam/topics/security-findings"
STORES = (entry(ALPHA, "backups", "ciamObjectStore", ciamBindingRole="ds-backups", ciamStorageRef="gs://ea-backups"),
          entry(ALPHA, "exports", "ciamObjectStore", ciamBindingRole="idm-exports", ciamStorageRef="gs://ea.exports"),
          entry(ALPHA, "grants", "ciamDatabase", ciamBindingRole="pf-grants-db", ciamDbEngine="postgresql"),
          entry(ALPHA, "findings", "ciamStreamBinding", ciamBindingRole="security-findings", ciamStreamKind="topic",
                ciamProviderRef=TOPIC))


def sdp(days="7", **more):
    return entry(ALPHA, "sdp", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                 ciamScansRole=("ds-backups", "idm-exports", "pf-grants-db"),
                 ciamCustomIdentifier=("cui-marking: CUI//[A-Z-]+",), ciamRescanDays=days,
                 ciamFindingsRole="security-findings", **more)


def _render(*bindings):
    _, alpha, _ = model(alpha=(*STORES, *bindings))
    return "\n\n".join(as_text(render_discovery(alpha))[0])


def test_a_template_and_a_discovery_config_over_the_buckets():
    out = _render(sdp(days="1", ciamResultsRole="ds-backups"))
    assert 'resource "google_data_loss_prevention_inspect_template" "sdp" {' in out
    assert 'name = "CUI_MARKING"' in out and 'pattern = "CUI//[A-Z-]+"' in out
    assert 'resource "google_data_loss_prevention_discovery_config" "sdp" {' in out
    assert 'parent            = "projects/${var.project_id}/locations/${var.region}"' in out
    assert "inspect_templates = [google_data_loss_prevention_inspect_template.sdp.id]" in out
    assert r'bucket_name_regex = "^(ea\\-backups|ea\\.exports)$"' in out
    assert 'refresh_frequency = "UPDATE_FREQUENCY_DAILY"' in out and 'status            = "RUNNING"' in out
    assert "google_workflows_workflow" not in out and "lifecycle" not in out
    assert out.count("pub_sub_notification {") == 2 and f'topic = "{TOPIC}"' in out
    assert "# sdp: only Cloud Storage targets are rendered: pf-grants-db not examined here" in out
    assert "# sdp: Sensitive Data Protection exports detailed profiles to BigQuery only: ds-backups isn't written to" \
        in out


def test_monthly_no_template_and_what_isnt_rendered():
    out = _render(entry(ALPHA, "sdp", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                        ciamScansRole=("ds-backups",), ciamRescanDays="30"))
    assert 'refresh_frequency = "UPDATE_FREQUENCY_MONTHLY"' in out and "inspect_template" not in out
    assert "pub_sub_notification" not in out and "profiled daily" not in out
    assert "# NOTE: data discovery sdp: no discovery config: it examines no Cloud Storage bucket here" in _render(
        entry(ALPHA, "sdp", "ciamDataDiscovery", ciamBindingRole="data-discovery", ciamScansRole=("pf-grants-db",)))
    assert _render(entry(ALPHA, "org", "ciamDataDiscovery", ciamBindingRole="data-discovery",
                         ciamManagedBy="cn=nobody,dc=ciam-ops")) == \
        "# Data discovery org: kept by cn=nobody,dc=ciam-ops, not rendered here"
    assert info_type("employee-id") == "EMPLOYEE_ID"


def test_read_back_from_state():
    tid = "projects/ea-ciam/locations/us-east4/inspectTemplates/ciam-sdp"
    pairs = [("google_data_loss_prevention_inspect_template", {
                 "id": tid, "inspect_config": [{"custom_info_types": [
                     {"info_type": [{"name": "CUI_MARKING"}], "regex": [{"pattern": "CUI//[A-Z-]+"}]}]}]}),
             ("google_data_loss_prevention_discovery_config", {
                 "id": "projects/ea-ciam/locations/us-east4/discoveryConfigs/dc1", "display_name": "sdp",
                 "inspect_templates": [tid],
                 "targets": [{"cloud_storage_target": [{
                     "filter": [{"collection": [{"include_regexes": [{"patterns": [{"cloud_storage_regex": [{
                         "bucket_name_regex": r"^(ea\-backups|ea\.exports)$"}]}]}]}]}],
                     "generation_cadence": [{"refresh_frequency": "UPDATE_FREQUENCY_DAILY"}]}]}],
                 "actions": [{"pub_sub_notification": [{"topic": TOPIC, "event": "NEW_PROFILE"}]}]})]
    (r,) = discovery_resources(pairs)
    assert (r.kind, r.name) == ("discovery", "sdp")
    assert dict(r.attrs) == {"ciamRescanDays": ("1",), "ciamCustomIdentifier": ("cui-marking: CUI//[A-Z-]+",)}
    assert dict(r.links) == {"ciamScansRole": ("ea-backups", "ea.exports"), "ciamFindingsRole": TOPIC}


def test_another_interval_is_a_paused_config_a_daily_workflow_resumes():
    d, alpha, beta = model(alpha=(*STORES, sdp()))
    hcl, files = as_text(render_discovery(alpha))
    out = "\n\n".join(hcl)
    assert ("# sdp: every 7 days: Sensitive Data Protection refreshes daily or monthly, so the config stays paused "
            "and workflow sdp-rescan-sdp resumes it daily") in out
    assert 'status            = "PAUSED"' in out and "ignore_changes = [status]" in out
    assert 'refresh_frequency = "UPDATE_FREQUENCY_DAILY"' in out                    # once resumed: at once
    assert 'resource "google_workflows_workflow" "sdp" {' in out
    assert 'source_contents = file("${path.module}/discovery/sdp-rescan.yaml")' in out
    assert "CONFIG      = google_data_loss_prevention_discovery_config.sdp.id" in out
    assert 'RESCAN_DAYS = "7"' in out and 'BUCKETS     = "ea-backups,ea.exports"' in out
    assert 'rescan-days = "7"' in out
    assert 'permissions = ["dlp.jobTriggers.get", "dlp.jobTriggers.update", "dlp.fileStoreProfiles.list"]' in out
    assert 'role    = "roles/workflows.invoker"' in out
    assert 'account_id   = "rescan-sdp-wf"' in out and 'account_id   = "rescan-sdp-run"' in out
    assert 'schedule  = "0 6 * * *"' in out
    assert ('uri         = "https://workflowexecutions.googleapis.com/v1/${google_workflows_workflow.sdp.id}/'
            'executions"') in out
    assert "service_account_email = google_service_account.sdp_rescan_scheduler.email" in out
    (path, text), = files.items()
    assert path == "terraform/discovery/sdp-rescan.yaml" and text.endswith(RESCAN_WORKFLOW)
    assert check_discovery_cadence(context(d, beta, alpha)).ok == (
        "alpha/prod's data discovery `sdp` examines its stores every 7 days: Cloud Scheduler starts workflow "
        "sdp-rescan-sdp daily, which resumes the paused config once 7 days have passed since the buckets' last "
        "successful profiles.",)


def test_under_dod_il4_or_il5_the_refresh_is_kept_and_the_plan_says_so():
    held = LdifRecord(ALPHA, "modify", {}, (("add", "objectClass", ("ciamEnvironmentPlacement",)),
                                            ("replace", "ciamRequiredAuthorization", ("dod-il5",))))
    d, alpha, beta = model(alpha=(*STORES, sdp()), changes=(held,))
    hcl, files = as_text(render_discovery(alpha))
    out = "\n\n".join(hcl)
    assert files == {} and "google_workflows_workflow" not in out and 'status            = "RUNNING"' in out
    assert "aren't on Assured Workloads' DoD IL4/IL5 supported products: profiled daily, more often than the record " \
           "asks" in out
    (action,) = check_discovery_cadence(context(d, beta, alpha, cutover="2026-12-01")).actions
    assert action[1].startswith("alpha/prod's data discovery `sdp` asks for every 7 days:")
    assert action[1].endswith("profiled daily (more often than asked). Accept it, or record an interval the refresh "
                              "offers (1 or 30).")


def test_the_interval_reads_back_from_the_workflow():
    d, alpha, _ = model(alpha=(*STORES, sdp()))
    provider = block(*TfBlock("provider", ("google",), (("project", "ea-ciam"), ("region", "us-east4"))))
    main = "\n\n".join(as_text(render_discovery(alpha))[0]) + "\n\n" + provider + "\n\n" + block(
        "variable", ["project_id"], [("default", "ea-ciam")]) + "\n\n" + block("variable", ["region"],
                                                                              [("default", "us-east4")])
    (text,) = rendered_states({"alpha/prod/main.tf": main}, d, "alpha/prod").values()
    found, problem = read_state(text)
    assert problem is None
    (r,) = discovery_resources([(x.type, x.attributes) for x in found if x.mode == "managed"])
    assert dict(r.attrs)["ciamRescanDays"] == ("7",)
    assert dict(r.links)["ciamScansRole"] == ("ea-backups", "ea.exports")
    workflow = next(x.attributes for x in found if x.type == "google_workflows_workflow")
    assert json.dumps(workflow["user_env_vars"]["RESCAN_DAYS"]) == '"7"'

