"""Splunk SIEM add-on (milestone 6.2e, decision 3046): the Splunk indexes an environment keeps logs in (log
destinations of kind siem-index named by their index) with their retention, the detections its alert rules are realized
by there as scheduled saved searches, and the Universal Forwarder inputs shipping the products' log files to them; read
back from the rendered .conf files and from the management API (read-only). It renders when the environment's stack
declares it (stack role siem) and keeps the Splunk indexes it names (siem_indexes), so the provider adapters leave
them to it."""
from opsdir.core.contract import Adapter, Importer, ReadBack
from .collect import COLLECTORS
from .naming import APP_DIR, SEARCH_LANGUAGE, SETTINGS, keeps
from .read import read_conf_files, read_rest
from .render import host_files, render, render_notes

ADAPTER = Adapter(name="splunk", kind="platform", applies=None, required_roles=(),
                  render_neutral=None, render_env=render, checks=(), ref_schemes=(), secret_schemes={},
                  renders="Splunk indexes and detections (the opsdir_ciam app) and Universal Forwarder inputs",
                  neutral_label=None, vocabulary={"ciamSearchLanguage": (SEARCH_LANGUAGE,)}, schema=None,
                  formats=((f"{APP_DIR}/*.conf", "ini"),),
                  products=(), secret_patterns=(),
                  importers=(Importer("rest", "Splunk's indexes (retention) and saved searches (detections), as the "
                                              "management API answers them, per <cloud>/<env>/", read_rest),
                             Importer("conf", "Splunk's indexes.conf and savedsearches.conf per <cloud>/<env>/",
                                      read_conf_files)),
                  profile_terms=None, access=None, collectors=COLLECTORS, settings=SETTINGS,
                  host_files=host_files, notes=render_notes,
                  # optional: an overlay inheriting its base's indexes renders none of them
                  reads_back=(ReadBack("conf", f"{APP_DIR}/*.conf", f"{APP_DIR}/", "{environment}/", True),),
                  siem_indexes=keeps)
