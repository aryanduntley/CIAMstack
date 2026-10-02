"""Azure messaging: Communication Services email domains read as sending identities (DKIM when the selectors its
verification records name are published in Azure DNS, SPF and DMARC from the TXT records), and Service Bus queues
and topics, Event Hubs and Event Grid topics as stream carriers, from Terraform state."""
import json

from opsdir_adapter_azure.inventory import state_resources

RG = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-ciam-prod/providers"
DOMAIN = f"{RG}/Microsoft.Communication/emailServices/ecs-ciam/domains/example.test"


def _state(*resources):
    return json.dumps({"version": 4, "terraform_version": "1.9.0", "resources": [
        {"mode": "managed", "type": t, "name": n, "provider": 'provider["registry.terraform.io/hashicorp/azurerm"]',
         "instances": [{"attributes": a}]} for t, n, a in resources]})


def _domain(*cnames):
    return _state(
        ("azurerm_email_communication_service_domain", "d", {
            "id": DOMAIN, "name": "example.test", "domain_management": "CustomerManaged", "tags": {"Role": "mail-sending"},
            "verification_records": [{"dkim": [{"name": "selector1-azurecomm-prod-net._domainkey"}],
                                      "dkim2": [{"name": "selector2-azurecomm-prod-net._domainkey"}]}]}),
        *(("azurerm_dns_cname_record", c, {"name": c, "zone_name": "example.test"}) for c in cnames),
        ("azurerm_dns_txt_record", "spf", {"name": "@", "zone_name": "example.test",
                                           "record": [{"value": "v=spf1 include:spf.protection.outlook.com -all"}]}),
        ("azurerm_dns_txt_record", "dmarc", {"name": "_dmarc", "zone_name": "example.test",
                                             "record": [{"value": "v=DMARC1; p=quarantine"}]}),
        ("azurerm_servicebus_queue", "crm", {"id": f"{RG}/Microsoft.ServiceBus/namespaces/sb/queues/crm", "name": "crm"}),
        ("azurerm_eventgrid_topic", "audit", {"id": f"{RG}/Microsoft.EventGrid/topics/audit", "name": "audit",
                                              "tags": {"Role": "audit-events"}}))


def _sending(state):
    resources, _ = state_resources(state)
    (acs,) = [r for r in resources if r.kind == "sending"]
    return acs


def test_a_domain_whose_dkim_selectors_are_published():
    acs = _sending(_domain("selector1-azurecomm-prod-net._domainkey", "selector2-azurecomm-prod-net._domainkey"))
    assert (acs.ref, acs.name, acs.role) == (DOMAIN, "acs-example.test", "mail-sending")
    assert acs.attrs == {"ciamSenderDomain": ("example.test",), "ciamDkimVerified": ("TRUE",),
                         "ciamSpfAuthorized": ("TRUE",), "ciamDmarcPolicy": ("quarantine",)}


def test_a_missing_selector_is_not_verified():
    assert _sending(_domain("selector1-azurecomm-prod-net._domainkey")).attrs["ciamDkimVerified"] == ("FALSE",)


def test_queues_and_topics_carry_streams():
    resources, _ = state_resources(_domain())
    assert {r.name: (r.attrs["ciamStreamKind"], r.role) for r in resources if r.kind == "stream"} == {
        "crm": (("queue",), None), "audit": (("topic",), "audit-events")}
