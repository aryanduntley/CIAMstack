"""Elastic Security SIEM add-on (task 552, milestone 109): the Elastic data streams an environment keeps logs in (log
destinations of kind siem-index named by their stream) with their index lifecycle and snapshot archive, and the
detections its alert rules are realized by there as ES|QL rules, rendered as Elasticsearch and Kibana API documents
and as Terraform for the elastic/elasticstack provider; read back from the Elasticsearch and Kibana APIs (read-only)
and from its own documents (the round trip). It renders when the environment's stack declares it (stack role siem)
and keeps the data streams it names (siem_indexes), so the provider adapters leave them to it."""
from opsdir.core.contract import Adapter, Importer, ReadBack
from .api import OUTPUT
from .collect import COLLECTORS
from .naming import LANGUAGES, SETTINGS, keeps
from .read import read_elasticsearch, read_kibana
from .render import TARGETS, render_env, render_notes

ADAPTER = Adapter(name="elastic", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render_env, checks=(), ref_schemes=(), secret_schemes={},
                  renders="Elastic data streams' index lifecycle and snapshot archive, and detections as ES|QL rules "
                          "(API documents and Terraform)",
                  neutral_label=None, vocabulary={"ciamSearchLanguage": LANGUAGES}, schema=None,
                  formats=((f"{OUTPUT}*.json", "json"), (f"{OUTPUT}*.ndjson", "ndjson"),
                           ("elastic/terraform/*.tf", "hcl")),
                  products=(), secret_patterns=(),
                  importers=(Importer("elasticsearch", "Elastic's data streams with their ILM and snapshot policies, "
                                                       "as Elasticsearch answers them, per <cloud>/<env>/",
                                      read_elasticsearch),
                             Importer("kibana", "Elastic Security's detection rules, as Kibana answers or exports "
                                                "them, per <cloud>/<env>/", read_kibana)),
                  profile_terms=None, access=None, collectors=COLLECTORS, settings=SETTINGS,
                  notes=render_notes, render_targets=TARGETS,
                  # optional: an overlay inheriting its base's streams renders none of them
                  reads_back=(ReadBack("elasticsearch", f"{OUTPUT}*.json", OUTPUT, "{environment}/", True),
                              ReadBack("kibana", f"{OUTPUT}*.ndjson", OUTPUT, "{environment}/", True)),
                  siem_indexes=keeps)
