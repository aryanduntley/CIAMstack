"""PingFederate Admin API payloads validated offline against the version's vendored spec: every supported version
loads with its requests; a valid payload passes; a wrong value, a misspelt or foreign property, a missing required one
and a request the API doesn't have are named with their JSON path; discriminated unions pick their schema by value;
a version maps to its spec, and one without a vendored spec to none."""
import json

import pytest

from opsdir_adapter_pingfederate.admin_api_spec import (VERSIONS, indexed, load_spec, request_problems, request_schema,
                                                        spec_version, validate)

LDAP = {"type": "LDAP", "id": "ds1", "ldapType": "PING_DS", "hostnames": ["ds-1.example.test:1636"],
        "userDN": "cn=pingfed,ou=services,dc=example", "password": "${secret:vault://kv/pf#ds-password}",
        "useSsl": True}
CLIENT = {"clientId": "portal", "name": "Portal", "grantTypes": ["AUTHORIZATION_CODE", "REFRESH_TOKEN"],
          "redirectUris": ["https://portal.example.test/cb"],
          "clientAuth": {"type": "SECRET", "secret": "${secret:vault://kv/pf#portal}"}}


@pytest.mark.parametrize("version", VERSIONS)
def test_every_supported_version_loads_with_the_requests_the_renderer_makes(version):
    spec = load_spec(version)
    assert spec["version"].startswith(version + ".")
    assert {request_schema(spec, m, p) for m, p in (("POST", "/dataStores"), ("PUT", "/dataStores/ds1"),
                                                     ("POST", "/oauth/clients"), ("PUT", "/oauth/clients/portal"),
                                                     ("PUT", "/idp/spConnections/sp1"))} == \
        {"DataStoreAggregation", "Client", "SpConnection"}
    assert request_problems(spec, "POST", "/dataStores", LDAP) == ()
    assert request_problems(spec, "PUT", "/oauth/clients/portal", CLIENT) == ()


def test_wrong_values_unknown_and_missing_properties_are_named_with_their_path():
    spec = load_spec("12.1")
    assert request_problems(spec, "PUT", "/dataStores/ds1", {**LDAP, "ldapType": "OPENLDAP", "hostName": "x"}) == (
        "$.ldapType: 'OPENLDAP' is not one of ACTIVE_DIRECTORY, ORACLE_DIRECTORY_SERVER, ORACLE_UNIFIED_DIRECTORY, "
        "UNBOUNDID_DS, PING_DIRECTORY, PING_DS, GENERIC", "$.hostName: not a property the spec names")
    assert request_problems(spec, "POST", "/oauth/clients", {"clientId": "a", "grantTypes": "IMPLICIT"}) == (
        "$: lacks name", "$.grantTypes: str where the spec wants array")
    assert request_problems(spec, "POST", "/oauth/clients", {**CLIENT, "grantTypes": ["AUTHORIZATION_CODE", 7]}) == (
        "$.grantTypes[1]: int where the spec wants string",)
    assert request_problems(spec, "POST", "/oauth/clients", {**CLIENT, "bypassApprovalPage": "yes"}) == (
        "$.bypassApprovalPage: str where the spec wants boolean",)
    assert request_problems(spec, "DELETE", "/dataStores/ds1", {}) == (
        "DELETE /dataStores/ds1: not a request of the Admin API 12.1.0.4",)


def test_a_discriminator_picks_the_schema_its_value_names():
    spec = load_spec("13.1")
    jdbc = {"type": "JDBC", "id": "db", "driverClass": "org.postgresql.Driver", "userName": "pf",
            "connectionUrl": "jdbc:postgresql://db.example.test/pf", "password": "${secret:vault://kv/pf#db}"}
    assert request_problems(spec, "POST", "/dataStores", jdbc) == ()
    assert "$.hostnames: not a property the spec names" in request_problems(
        spec, "POST", "/dataStores", {**jdbc, "hostnames": ["ds-1"]})          # an LDAP store's property on a JDBC one


def test_a_base_schema_with_subtypes_accepts_any_subtype_and_booleans_are_not_numbers():
    spec = indexed({"version": "t", "requests": {}, "schemas": {
        "Shape": {"discriminator": {"propertyName": "kind"}, "properties": {"kind": {"type": "string"}},
                  "required": ["kind"]},
        "Circle": {"allOf": [{"$ref": "#/components/schemas/Shape"},
                             {"properties": {"radius": {"type": "number"}}, "required": ["radius"]}]},
        "Square": {"allOf": [{"$ref": "#/components/schemas/Shape"}, {"properties": {"side": {"type": "integer"}}}]},
        "Box": {"properties": {"shape": {"$ref": "#/components/schemas/Shape"},
                               "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                               "tags": {"type": "array", "items": {"type": "string"}, "uniqueItems": True}}}}})
    box = {"$ref": "#/components/schemas/Box"}
    assert validate(spec, box, {"shape": {"kind": "circle", "radius": 2.5}, "labels": {"a": "b"}}) == ()
    assert validate(spec, box, {"shape": {"kind": "square", "side": 3}}) == ()
    assert validate(spec, box, {"shape": {"kind": "square", "side": True}}) == (
        "$.shape.side: bool where the spec wants integer",)
    assert validate(spec, box, {"labels": {"a": 1}, "tags": ["x", "x"]}) == (
        "$.labels.a: int where the spec wants string", "$.tags: repeated items")


@pytest.mark.parametrize("version", VERSIONS)
def test_every_request_schema_of_every_version_can_be_checked(version):
    spec = load_spec(version)
    assert all(isinstance(request_problems(spec, k.split(" ", 1)[0], k.split(" ", 1)[1], {}), tuple)
               for k in spec["requests"])


def test_a_version_maps_to_its_spec_or_none():
    assert [spec_version(v) for v in ("PingFederate 12.1.4", "13.1", "PingFederate 13.0.5", "PingFederate 11.3.2",
                                      "PingFederate 12.0.1", "", None, "PingAM 7.5")] == \
        ["12.1", "13.1", "13.0", None, None, None, None, None]


def test_the_vendored_specs_name_their_source_and_carry_the_upstream_license():
    from importlib import resources
    folder = resources.files("opsdir_adapter_pingfederate").joinpath("specs")
    assert "Apache License" in folder.joinpath("LICENSE-pingfederate-go-client.md").read_text()
    assert all(json.loads(folder.joinpath(f"admin-api-{v}.json").read_text())["source"].startswith(
        "pingfederate-go-client v") for v in VERSIONS)
