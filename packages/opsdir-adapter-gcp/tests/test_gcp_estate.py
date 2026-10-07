"""The estate's tag policy and project on Google Cloud: the policy as the provider's default labels in label form
(lowercase keys and values, [a-z0-9_-]), the recorded project as each root's project_id default, and imported labels
judged against the policy's keys case and punctuation aside."""
import json

import pytest

from opsdir.connectors.importing import import_changes
from opsdir.connectors.prerequisites import prerequisite_rows
from opsdir.core.interchange.ldif import LdifRecord
from opsdir.core.inventory import resource
from opsdir.domains.estate.tags import tag_notices
from opsdir_adapter_gcp.account import default_labels, label_key, project_variable, provider_block
from opsdir_adapter_gcp.adapter import ADAPTER
from opsdir_adapter_gcp.regions import read_regions, region_rows
from estate_fixtures import estate

REGIONS = [{"kind": "compute#region", "name": "us-central1", "description": "us-central1", "status": "UP"},
           {"kind": "compute#region", "name": "europe-west1", "description": "europe-west1", "status": "UP"},
           {"kind": "compute#zone", "name": "us-central1-a"}]


def test_the_policy_as_default_labels():
    _, d, alpha, beta = estate(account="example-ciam-prod")
    assert default_labels(alpha) == {"cloud": "alpha", "costcenter": "cc-1234", "dataclass": "confidential",
                                     "environment": "alpha-prod", "estate": "example", "owner": "platform"}
    assert provider_block(alpha, ("project", "p")) == """provider "google" {
  project = "p"
  default_labels = {
    cloud       = "alpha"
    costcenter  = "cc-1234"
    dataclass   = "confidential"
    environment = "alpha-prod"
    estate      = "example"
    owner       = "platform"
  }
}"""
    assert "default_labels" not in provider_block(estate(rules=())[2], ("project", "p"))
    assert label_key("9Data.Class") == "data-class" and label_key("---") == "tag"


def test_the_recorded_project_is_the_default():
    _, d, alpha, beta = estate(account="example-ciam-prod")
    assert 'default     = "example-ciam-prod"' in project_variable(alpha, described=True)
    assert project_variable(beta) == 'variable "project_id" {\n  type = string\n}'


def test_labels_match_the_policy_s_keys_in_label_form():
    _, d, *_ = estate()
    labelled = resource("server", "i-1", name="ds-1", tags={"owner": "platform", "costcenter": "cc-1234",
                                                             "dataclass": "internal", "environment": "alpha-prod",
                                                             "cloud": "alpha", "estate": "example"})
    assert tag_notices(d, "alpha/prod", (labelled,)) == ()


def test_the_region_list_reads_gcloud_compute_regions():
    assert region_rows(REGIONS) == (("us-central1", None, None, "available", "public"),
                                    ("europe-west1", None, None, "available", "public"))
    _, d, *_ = estate()
    imported = read_regions({"regions.json": json.dumps(REGIONS), "x.txt": "no"}, d, ())
    assert [r.dn for r in import_changes(d, imported)][2:] == [
        "cn=europe-west1,cn=gcp,ou=regions,dc=ciam-ops", "cn=us-central1,cn=gcp,ou=regions,dc=ciam-ops"]
    assert imported.notices[-1] == "x.txt: not `gcloud compute regions list` output; not read"
    with pytest.raises(SystemExit, match="gcp: the export lists no regions"):
        read_regions({"regions.json": json.dumps(REGIONS[2:])}, d, ())


def test_the_region_list_is_a_prerequisite_fetched_by_running_gcloud():
    _, d, *_ = estate()
    assert prerequisite_rows(d, (ADAPTER,)) == (
        ("gcp-regions", "gcp", "not needed yet", "opsdir import gcp/regions --run",
         "gcloud compute regions list --format=json > regions.json"),)


def test_the_provider_notes_that_google_cloud_has_no_fips_endpoints_to_switch_to():
    fips = LdifRecord("cloud=alpha,ou=environments,dc=ciam-ops", "modify", {},
                      (("add", "objectClass", ("ciamCloudEndpoints",)), ("replace", "ciamFipsEndpoints", ("TRUE",))))
    _, d, alpha, beta = estate(rules=(), extra=(fips,))
    assert provider_block(alpha, ("project", "p")) == (
        'provider "google" {\n  # FIPS endpoints: the google provider has no FIPS endpoint switch; FIPS 140 is met by '
        'Google Cloud\'s own validated modules, or enforced for a folder with Assured Workloads\n  project = "p"\n}')
    assert "FIPS" not in provider_block(beta, ("project", "p"))
