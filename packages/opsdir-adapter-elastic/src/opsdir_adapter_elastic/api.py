"""What the Elastic add-on renders for an environment as Elasticsearch and Kibana API documents (render target api).
Pure.

  elastic/api/ilm-policies.json         the data streams' ILM policies, as GET _ilm/policy answers them (lifecycle)
  elastic/api/component-templates.json  the dataset hooks attaching them, as GET _component_template answers them
  elastic/api/slm-policies.json         the archives' snapshot policies, as GET _slm/policy answers them (when any)
  elastic/api/data-stream-lifecycles.json  on Elastic Cloud Serverless, instead of the three above: the data
                                        streams' data stream lifecycles, as GET _data_stream/<name>/_lifecycle
                                        answers them (lifecycle)
  elastic/api/detection-rules.ndjson    the detections as ES|QL rules, one per line: what POST
                                        /api/detection_engine/rules/_import takes (detections)
  elastic/api/fleet-agent-policies.json    the Fleet agent policies shipping the logs (shipping), each what POST
                                        /api/fleet/agent_policies takes
  elastic/api/fleet-package-policies.json  their integration policies, each what POST
                                        /api/fleet/package_policies?format=simplified takes (the integration package
                                        installed first: POST /api/fleet/epm/packages/<name>/<version>)

Each policy and template is PUT under its name (PUT _ilm/policy/<name> with {"policy": ...}, PUT
_component_template/<name>, PUT _slm/policy/<name> with the policy's body, PUT _data_stream/<name>/_lifecycle with
its lifecycle); the importers read the same files back (the round trip; the Fleet policies aren't read back). JSON has
no comments: the render notes are the adapter's notes (render_notes).
"""
import json

from opsdir.core.jsondata import indented
from .detections import rendered_rules
from .lifecycle import (component_template, data_stream_lifecycle, ilm_policy, lifecycle_streams, rendered_streams,
                        slm_policy)
from .naming import serverless
from .shipping import fleet_policies

OUTPUT = "elastic/api/"
ILM_POLICIES, COMPONENT_TEMPLATES, SLM_POLICIES = "ilm-policies.json", "component-templates.json", "slm-policies.json"
DETECTION_RULES = "detection-rules.ndjson"
DATA_STREAM_LIFECYCLES = "data-stream-lifecycles.json"
FLEET_AGENT_POLICIES, FLEET_PACKAGE_POLICIES = "fleet-agent-policies.json", "fleet-package-policies.json"


def ndjson(documents):
    """Documents as newline-delimited JSON: one compact document per line."""
    return "".join(json.dumps(d, separators=(",", ":")) + "\n" for d in documents)


def _retention_files(m):
    if serverless(m):
        lifecycles = [{"name": s, "lifecycle": lc} for s, lc in map(data_stream_lifecycle, lifecycle_streams(m))]
        return {f"{OUTPUT}{DATA_STREAM_LIFECYCLES}": indented({"data_streams": lifecycles})} if lifecycles else {}
    streams = rendered_streams(m)
    policies = dict(p for p in map(ilm_policy, streams) if p is not None)
    archives = dict(p for p in map(slm_policy, streams) if p is not None)
    templates = [{"name": n, "component_template": t} for n, t in map(component_template, streams)]
    return {**({f"{OUTPUT}{ILM_POLICIES}": indented(policies)} if policies else {}),
            **({f"{OUTPUT}{COMPONENT_TEMPLATES}": indented({"component_templates": templates})} if templates else {}),
            **({f"{OUTPUT}{SLM_POLICIES}": indented(archives)} if archives else {})}


def api_files(m, services):
    """{elastic/api/<file>: text}: environment m's data streams' retention (policies and templates; on Serverless
    their data stream lifecycles), its detections' rules and the Fleet policies shipping its logs, each file only
    when it holds something."""
    rules = tuple(body for _, body in rendered_rules(m))
    agents, packages = fleet_policies(m, services)
    return {**_retention_files(m),
            **({f"{OUTPUT}{DETECTION_RULES}": ndjson(rules)} if rules else {}),
            **({f"{OUTPUT}{FLEET_AGENT_POLICIES}": indented({"items": list(agents)})} if agents else {}),
            **({f"{OUTPUT}{FLEET_PACKAGE_POLICIES}": indented({"items": list(packages)})} if packages else {})}
