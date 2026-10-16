"""What the Elastic add-on renders for an environment as Elasticsearch and Kibana API documents (render target api).
Pure.

  elastic/api/ilm-policies.json         the data streams' ILM policies, as GET _ilm/policy answers them (lifecycle)
  elastic/api/component-templates.json  the dataset hooks attaching them, as GET _component_template answers them
  elastic/api/slm-policies.json         the archives' snapshot policies, as GET _slm/policy answers them (when any)
  elastic/api/detection-rules.ndjson    the detections as ES|QL rules, one per line: what POST
                                        /api/detection_engine/rules/_import takes (detections)

Each policy and template is PUT under its name (PUT _ilm/policy/<name> with {"policy": ...}, PUT
_component_template/<name>, PUT _slm/policy/<name> with the policy's body); the importers read the same files back
(the round trip). JSON has no comments: the render notes are the adapter's notes (render_notes).
"""
import json

from opsdir.core.jsondata import indented
from .detections import rendered_rules
from .lifecycle import component_template, ilm_policy, rendered_streams, slm_policy

OUTPUT = "elastic/api/"
ILM_POLICIES, COMPONENT_TEMPLATES, SLM_POLICIES = "ilm-policies.json", "component-templates.json", "slm-policies.json"
DETECTION_RULES = "detection-rules.ndjson"


def ndjson(documents):
    """Documents as newline-delimited JSON: one compact document per line."""
    return "".join(json.dumps(d, separators=(",", ":")) + "\n" for d in documents)


def api_files(m):
    """{elastic/api/<file>: text}: environment m's data streams' policies and templates and its detections' rules, each
    file only when it holds something."""
    streams = rendered_streams(m)
    policies = dict(p for p in map(ilm_policy, streams) if p is not None)
    archives = dict(p for p in map(slm_policy, streams) if p is not None)
    templates = [{"name": n, "component_template": t} for n, t in map(component_template, streams)]
    rules = tuple(body for _, body in rendered_rules(m))
    return {**({f"{OUTPUT}{ILM_POLICIES}": indented(policies)} if policies else {}),
            **({f"{OUTPUT}{COMPONENT_TEMPLATES}": indented({"component_templates": templates})} if templates else {}),
            **({f"{OUTPUT}{SLM_POLICIES}": indented(archives)} if archives else {}),
            **({f"{OUTPUT}{DETECTION_RULES}": ndjson(rules)} if rules else {})}
