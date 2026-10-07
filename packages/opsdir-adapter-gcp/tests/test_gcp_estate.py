"""The estate's tag policy and project on Google Cloud: the policy as the provider's default labels in label form
(lowercase keys and values, [a-z0-9_-]), the recorded project as each root's project_id default, and imported labels
judged against the policy's keys case and punctuation aside."""
from opsdir.core.inventory import resource
from opsdir.domains.estate.tags import tag_notices
from opsdir_adapter_gcp.account import default_labels, label_key, project_variable, provider_block
from estate_fixtures import estate


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
