"""What the Elastic add-on renders for an environment as Terraform for Elastic's elastic/elasticstack provider (render
target terraform), from the same documents the api target writes, so both say the same thing. Pure.

  elastic/terraform/versions.tf   the provider, pinned to its current release line (~> 0.16.6), its Elasticsearch and
                                  Kibana connections left empty: the endpoints and API keys come from the provider's
                                  environment variables (ELASTICSEARCH_ENDPOINTS, ELASTICSEARCH_API_KEY,
                                  KIBANA_ENDPOINT, KIBANA_API_KEY), never from the files
  elastic/terraform/main.tf       the render notes as comments, then per data stream its ILM policy
                                  (elasticstack_elasticsearch_index_lifecycle), the component template attaching it
                                  (elasticstack_elasticsearch_component_template) and its snapshot policy
                                  (elasticstack_elasticsearch_snapshot_lifecycle), and per detection its ES|QL rule
                                  (elasticstack_kibana_security_detection_rule, in the Kibana space the estate setting
                                  elastic-kibana-space names when it isn't the default one)

A rule Terraform creates runs as the API key that applied it (Kibana keeps the key with the rule): apply with the
Elastic team's rule-managing key, never the collector's read-only one.
"""
from opsdir.core.directory import rdn_value
from opsdir.core.manifest import header
from opsdir.core.notes import note_comment
from opsdir.core.settings import setting_value
from opsdir_format_terraform.format import FORMAT as HCL
from opsdir_format_terraform.hcl import Block, Expr, NestedBlock, block, data_block, data_value, tf_name
from .detections import rendered_rules
from .lifecycle import component_template, ilm_policy, rendered_streams, slm_policy
from .naming import KIBANA_SPACE

OUTPUT = "elastic/terraform/"
SOURCE, VERSION = "elastic/elasticstack", "~> 0.16.6"
# The provider's connections, empty: endpoints and credentials come only from the ELASTICSEARCH_* / KIBANA_* env vars
PROVIDER = block("provider", ("elasticstack",), (("elasticsearch", Block(())), ("kibana", Block(())))) + "\n"


def _encoded(value, indent):
    """A JSON document as a jsonencode() expression of the HCL object it is (laid out like terraform fmt)."""
    return Expr(f"jsonencode({data_value(value, indent)})")


def _phase(spec):
    """An ILM phase ({min_age, actions}) as the provider's phase block: min_age, then a block per action."""
    return NestedBlock((("min_age", spec["min_age"]),
                        *((action, NestedBlock(tuple(args.items()))) for action, args in spec["actions"].items())))


def lifecycle_block(name, body):
    """The elasticstack_elasticsearch_index_lifecycle block of an ILM policy (its name, GET _ilm/policy body)."""
    policy = body["policy"]
    return data_block("resource", ["elasticstack_elasticsearch_index_lifecycle", tf_name(name)], [
        ("name", name), ("metadata", _encoded(policy["_meta"], 1)),
        *((phase, _phase(spec)) for phase, spec in policy["phases"].items())])


def template_block(name, body):
    """The elasticstack_elasticsearch_component_template block of a component template (its name, body)."""
    return data_block("resource", ["elasticstack_elasticsearch_component_template", tf_name(name)], [
        ("name", name), ("metadata", _encoded(body["_meta"], 1)),
        ("template", NestedBlock((("settings", _encoded(body["template"]["settings"], 2)),)))])


def snapshot_block(name, body):
    """The elasticstack_elasticsearch_snapshot_lifecycle block of an SLM policy (its name, GET _slm/policy body)."""
    policy = body["policy"]
    return data_block("resource", ["elasticstack_elasticsearch_snapshot_lifecycle", tf_name(name)], [
        ("name", name), ("repository", policy["repository"]), ("schedule", policy["schedule"]),
        ("snapshot_name", policy["name"]), ("indices", policy["config"]["indices"]),
        ("include_global_state", policy["config"]["include_global_state"]),
        *((("expire_after", policy["retention"]["expire_after"]),) if "retention" in policy else ())])


def rule_block(name, body, space):
    """The elasticstack_kibana_security_detection_rule block of a detection rule (the binding's name, the rule as the
    API takes it), in Kibana space space (None: the default space)."""
    return data_block("resource", ["elasticstack_kibana_security_detection_rule", tf_name(name)], [
        *((("space_id", space),) if space else ()), *body.items()])


def terraform_files(m, notes):
    """{elastic/terraform/<file>: text}: environment m's data streams' policies and templates and its detections'
    rules as Terraform, notes (RenderNotes) as comments at the top of main.tf; nothing when it renders none."""
    streams, rules = rendered_streams(m), rendered_rules(m)
    space = setting_value(m.d, KIBANA_SPACE)
    blocks = (*(b for s in streams for b in (
                  *(lifecycle_block(*p) for p in (ilm_policy(s),) if p is not None),
                  template_block(*component_template(s)),
                  *(snapshot_block(*p) for p in (slm_policy(s),) if p is not None))),
              *(rule_block(rdn_value(spec.alarm), body, None if space == KIBANA_SPACE.default else space)
                for spec, body in rules))
    if not blocks:
        return {}
    comments = "".join(f"# {note_comment(n)}\n" for n in notes)
    return {f"{OUTPUT}versions.tf": header(m, "Terraform provider for Elastic", HCL) + "\n" + data_block(
                "terraform", [], [("required_providers", NestedBlock((("elasticstack", {
                    "source": SOURCE, "version": VERSION}),)))]) + "\n\n" + PROVIDER,
            f"{OUTPUT}main.tf": header(m, "Elastic data streams' lifecycle and detection rules", HCL) + comments
            + "\n" + "\n\n".join(blocks) + "\n"}
