"""The showcase's PingFederate configuration as Admin API requests: every environment's requests, after the approved
changes, valid against the Admin API spec of the version its PingFederate servers run (the held settings, exported from
another version, named where it differs), secrets only as references."""
import json
import re

import pytest

from opsdir.core.directory import one
from opsdir.core.environment import env_model
from opsdir.core.versions import parsed, product_version
from opsdir.domains.compute.workloads import recorded_versions
from opsdir_adapter_pingfederate.admin_api import OUTPUT, admin_api_files
from opsdir_adapter_pingfederate.admin_api_spec import load_spec, spec_version
from opsdir_adapter_pingfederate.diagnostics import held_objects
from showcase_support import APPROVED, fixture_directory

ENVIRONMENTS = ("source/prod", "source/stage", "target/prod", "standby/prod", "hq/lab")


@pytest.fixture(scope="module")
def estate():
    return fixture_directory(APPROVED)


@pytest.mark.parametrize("env", ENVIRONMENTS)
def test_every_request_is_valid_against_the_version_its_servers_run(estate, env):
    m = env_model(estate, env)
    doc = json.loads(admin_api_files(m)[OUTPUT])
    (version,) = set(recorded_versions(m, "pf-engine"))        # the version the environment's engines record
    assert (doc["pingFederate"], doc["adminApi"]) == (version, load_spec(spec_version(version))["version"])
    assert [p for p in doc["problems"] if p.split(" ", 1)[0] in ("PUT", "POST")] == []     # nothing the spec refuses
    exported = {one(e, "pingfedSourceVersion") for e in held_objects(m)} - {None}
    assert exported                                         # the showcase's PingFederate settings come from its export
    differs = {s for s in exported if parsed(s) != parsed(product_version(version)[1])}
    assert {p.split(",", 1)[0] for p in doc["problems"] if p.startswith("held settings exported")} == \
        {f"held settings exported from PingFederate {s}" for s in differs}
    assert len(doc["requests"]) >= 20


@pytest.mark.parametrize("env", ENVIRONMENTS)
def test_secrets_are_only_references(estate, env):
    text = admin_api_files(env_model(estate, env))[OUTPUT]
    passwords = re.findall(r'"(?:password|secret|value)": "([^"]*)"', text)
    assert not [p for p in passwords if re.search(r"(?i)secret|pass", p) and not p.startswith(("${", "UNBOUND:"))]
