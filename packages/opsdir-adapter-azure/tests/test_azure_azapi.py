"""Reading back an azapi resource's body from its state attributes (the read-backs of continuous exports, suppression
rules, VPN connections and Purview scans share it): an object as it is, JSON text parsed, anything else nothing."""
from opsdir_adapter_azure.azapi import azapi_body
from opsdir_adapter_azure.network_inventory import azapi_connections
from opsdir_adapter_azure.purview import API, SOURCES, TRIGGERS, purview_read
from opsdir_adapter_azure.security import azapi_automations
from opsdir_adapter_azure.suppressions import suppression_resources

BODY = {"properties": {"comment": "exception exc-1", "alertType": "K8S_X"}}


def test_an_azapi_body_an_object_or_json_text_else_nothing():
    assert azapi_body({"body": BODY}) == BODY
    assert azapi_body({"body": '{"properties": {"a": 1}}'}) == {"properties": {"a": 1}}
    for attrs in ({}, {"body": None}, {"body": "not json"}, {"body": "[1, 2]"}, {"body": [1]}, {"body": 3}):
        assert azapi_body(attrs) == {}


def test_the_read_backs_read_an_object_and_json_text_alike():
    rule = {"id": "/subscriptions/s/providers/Microsoft.Security/alertsSuppressionRules/r", "name": "r",
            "type": "Microsoft.Security/alertsSuppressionRules@2019-01-01-preview"}
    as_text = {**rule, "body": '{"properties": {"comment": "exception exc-1", "alertType": "K8S_X"}}'}
    assert suppression_resources([("azapi_resource", {**rule, "body": BODY})]) == \
        suppression_resources([("azapi_resource", as_text)])
    (found,) = suppression_resources([("azapi_resource", as_text)])
    assert found.attrs["ciamExceptionRef"] == ("exc-1",) and found.attrs["ciamFindingRef"] == ("azure:alerts:K8S_X",)
    connection = {"id": "/subscriptions/s/connections/cn-1", "name": "cn-1", "tags": {"Role": "vpn"},
                  "type": "Microsoft.Network/connections@2025-07-01"}
    props = {"properties": {"connectionType": "IPsec", "enableBgp": True}}
    assert len(azapi_connections([("azapi_resource", {**connection, "body": props})])) == 1
    assert azapi_connections([("azapi_resource", {**connection, "body": props})]) == \
        azapi_connections([("azapi_resource", {**connection, "body": '{"properties": {"connectionType": "IPsec", '
                                                                     '"enableBgp": true}}'})])
    automation = {"id": "a", "name": "export", "type": "Microsoft.Security/automations@2023-12-01-preview"}
    assert len(azapi_automations([("azapi_resource", {**automation, "body": {"properties": {}}})])) == 1
    assert azapi_automations([("azapi_resource", {**automation, "body": {"properties": {"isEnabled": True}}})]) == \
        azapi_automations([("azapi_resource", {**automation, "body": '{"properties": {"isEnabled": true}}'})])


def test_a_purview_trigger_reads_its_recurrence_from_its_body():
    parent = "acct.purview.azure.com/scan/datasources/src/scans/scan-1"
    trigger = {"type": f"{TRIGGERS}@{API}", "parent_id": parent,
               "body": {"properties": {"recurrence": {"frequency": "Day", "interval": 7}}}}
    source = {"type": f"{SOURCES}@{API}", "name": "src",
              "parent_id": "acct.purview.azure.com/scan",
              "body": {"properties": {"endpoint": "https://store1.blob.core.windows.net/"}}}
    (read,) = purview_read([("azapi_data_plane_resource", trigger), ("azapi_data_plane_resource", source)])
    assert (read.scan, read.account, read.storage, read.days) == ("scan-1", "acct", ("store1",), 7)
