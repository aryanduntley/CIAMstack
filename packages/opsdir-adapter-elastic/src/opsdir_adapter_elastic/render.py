"""What the Elastic add-on renders for an environment (decision on task 552), in the render targets chosen: the
Elasticsearch and Kibana API documents (api) and Terraform for the elastic/elasticstack provider (terraform), both by
default, from the same documents: the data streams' retention, the detections' rules and the Fleet policies shipping
the logs there; and the render notes of what it leaves to the Elastic team. Pure.
"""
from opsdir.core.notes import note
from .adopted import adopted_notes, native_bodies
from .api import api_files
from .detections import detection_notes, elastic_detections, rendered_rules
from .lifecycle import lifecycle_notes
from .fleet import elastic_shipments
from .naming import kept_streams
from .shipping import shipping_notes
from .terraform import terraform_files

TARGETS = (("api", "Elasticsearch and Kibana API documents: ILM, component template and SLM policies (on Serverless "
                   "data stream lifecycles), detection rules to import and Fleet policies (elastic/api/)"),
           ("terraform", "Terraform for the elastic/elasticstack provider (elastic/terraform/)"))


def _team_notes(m, services):
    return ((note("Monitoring", "action", "Elastic rule actions", "the detections' rules raise alerts, but who they "
                  "notify (their actions and connectors) is set in Kibana, not rendered",
                  ("Give each detection rule the actions that reach the channel its alert rule names",), None,
                  m.label),) if rendered_rules(m) or native_bodies(m, services) else ())


def render_notes(m, services):
    """Adapter notes: what environment m's Elastic render leaves out or to a person."""
    return (*_team_notes(m, services), *lifecycle_notes(m), *detection_notes(m), *adopted_notes(m, services),
            *shipping_notes(m, services))


def render_env(m, services, targets=tuple(t[0] for t in TARGETS)):
    """Adapter render_env: environment m's Elastic data streams' lifecycle, detection rules and log shipping in the
    render targets chosen, when it keeps logs in an Elastic data stream, runs a detection on one or ships logs to
    one."""
    if not kept_streams(m) and not elastic_detections(m) and not elastic_shipments(m, services):
        return {}
    return {**(api_files(m, services) if "api" in targets else {}),
            **(terraform_files(m, render_notes(m, services), services) if "terraform" in targets else {})}
