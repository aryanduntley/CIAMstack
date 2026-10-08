"""Data discovery on Google Cloud as Sensitive Data Protection: an inspect template with the own data types as custom
regular-expression info types, a discovery config profiling the examined Cloud Storage buckets (daily, or monthly from
30 days) with Pub/Sub notifications to the findings topic; other stores, BigQuery-only results and someone else's
discovery in comments; read back from state."""
from opsdir_adapter_gcp.discovery import discovery_resources, info_type, render_discovery
from network_fixtures import ALPHA, entry, model

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
    return "\n\n".join(render_discovery(alpha))


def test_a_template_and_a_discovery_config_over_the_buckets():
    out = _render(sdp(ciamResultsRole="ds-backups"))
    assert 'resource "google_data_loss_prevention_inspect_template" "sdp" {' in out
    assert 'name = "CUI_MARKING"' in out and 'pattern = "CUI//[A-Z-]+"' in out
    assert 'resource "google_data_loss_prevention_discovery_config" "sdp" {' in out
    assert 'parent            = "projects/${var.project_id}/locations/${var.region}"' in out
    assert "inspect_templates = [google_data_loss_prevention_inspect_template.sdp.id]" in out
    assert r'bucket_name_regex = "^(ea\\-backups|ea\\.exports)$"' in out
    assert 'refresh_frequency = "UPDATE_FREQUENCY_DAILY"' in out
    assert "# sdp: Sensitive Data Protection refreshes profiles daily or monthly: the record asks every 7 days, " \
           "profiled daily" in out
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
