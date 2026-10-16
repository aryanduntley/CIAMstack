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
                                  elastic-kibana-space names when it isn't the default one); on Elastic Cloud
                                  Serverless, instead of the policies and template, each stream's data stream
                                  lifecycle (elasticstack_elasticsearch_data_stream_lifecycle); then the Fleet
                                  integration packages the shipping policies use (elasticstack_fleet_integration),
                                  their agent policies (elasticstack_fleet_agent_policy) and integration policies
                                  (elasticstack_fleet_integration_policy, inputs as the provider's map since 0.14)

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
from .lifecycle import (component_template, data_stream_lifecycle, ilm_policy, lifecycle_streams, rendered_streams,
                        slm_policy)
from .naming import KIBANA_SPACE, serverless
from .shipping import fleet_policies

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


def data_stream_lifecycle_block(stream, lifecycle):
    """The elasticstack_elasticsearch_data_stream_lifecycle block of a data stream's lifecycle (its name, GET
    _data_stream/<name>/_lifecycle body)."""
    return data_block("resource", ["elasticstack_elasticsearch_data_stream_lifecycle", tf_name(stream)], [
        ("name", stream), *lifecycle.items()])


def integration_block(package):
    """The elasticstack_fleet_integration block installing a Fleet integration package ({name, version})."""
    return data_block("resource", ["elasticstack_fleet_integration", tf_name(package["name"])], [
        ("name", package["name"]), ("version", package["version"])])


def agent_policy_block(body):
    """The elasticstack_fleet_agent_policy block of an agent policy (as POST /api/fleet/agent_policies takes it)."""
    return data_block("resource", ["elasticstack_fleet_agent_policy", tf_name(body["id"])], [
        ("policy_id", body["id"]), ("name", body["name"]), ("namespace", body["namespace"]),
        ("description", body["description"]), ("monitor_logs", "logs" in body["monitoring_enabled"]),
        ("monitor_metrics", "metrics" in body["monitoring_enabled"])])


def _inputs(inputs):
    """An integration policy's inputs as the provider's inputs map, each stream's vars as a jsonencode() expression."""
    return {key: {"enabled": spec["enabled"],
                  **({"streams": {s: {"enabled": stream["enabled"], "vars": _encoded(stream["vars"], 5)}
                                  for s, stream in spec["streams"].items()}} if spec.get("streams") else {})}
            for key, spec in inputs.items()}


def package_policy_block(body):
    """The elasticstack_fleet_integration_policy block of an integration policy (as POST
    /api/fleet/package_policies?format=simplified takes it), referring to its agent policy and package blocks."""
    agent, package = tf_name(body["policy_ids"][0]), tf_name(body["package"]["name"])
    return data_block("resource", ["elasticstack_fleet_integration_policy", tf_name(body["id"])], [
        ("policy_id", body["id"]), ("name", body["name"]), ("namespace", body["namespace"]),
        ("description", body["description"]),
        ("agent_policy_id", Expr(f"elasticstack_fleet_agent_policy.{agent}.policy_id")),
        ("integration_name", Expr(f"elasticstack_fleet_integration.{package}.name")),
        ("integration_version", Expr(f"elasticstack_fleet_integration.{package}.version")),
        ("inputs", _inputs(body["inputs"]))])


def _retention_blocks(m):
    if serverless(m):
        return tuple(data_stream_lifecycle_block(*p) for p in map(data_stream_lifecycle, lifecycle_streams(m)))
    return tuple(b for s in rendered_streams(m) for b in (
        *(lifecycle_block(*p) for p in (ilm_policy(s),) if p is not None),
        template_block(*component_template(s)),
        *(snapshot_block(*p) for p in (slm_policy(s),) if p is not None)))


def _fleet_blocks(m, services):
    agents, packages = fleet_policies(m, services)
    used = tuple({p["package"]["name"]: p["package"] for p in packages}.values())
    return (*map(integration_block, used), *map(agent_policy_block, agents), *map(package_policy_block, packages))


def rule_block(name, body, space):
    """The elasticstack_kibana_security_detection_rule block of a detection rule (the binding's name, the rule as the
    API takes it), in Kibana space space (None: the default space)."""
    return data_block("resource", ["elasticstack_kibana_security_detection_rule", tf_name(name)], [
        *((("space_id", space),) if space else ()), *body.items()])


def terraform_files(m, notes, services):
    """{elastic/terraform/<file>: text}: environment m's data streams' retention, its detections' rules and the Fleet
    policies shipping its logs as Terraform, notes (RenderNotes) as comments at the top of main.tf; nothing when it
    renders none."""
    space = setting_value(m.d, KIBANA_SPACE)
    blocks = (*_retention_blocks(m),
              *(rule_block(rdn_value(spec.alarm), body, None if space == KIBANA_SPACE.default else space)
                for spec, body in rendered_rules(m)),
              *_fleet_blocks(m, services))
    if not blocks:
        return {}
    comments = "".join(f"# {note_comment(n)}\n" for n in notes)
    return {f"{OUTPUT}versions.tf": header(m, "Terraform provider for Elastic", HCL) + "\n" + data_block(
                "terraform", [], [("required_providers", NestedBlock((("elasticstack", {
                    "source": SOURCE, "version": VERSION}),)))]) + "\n\n" + PROVIDER,
            f"{OUTPUT}main.tf": header(m, "Elastic data streams' lifecycle, detection rules and Fleet policies", HCL)
            + comments
            + "\n" + "\n\n".join(blocks) + "\n"}
