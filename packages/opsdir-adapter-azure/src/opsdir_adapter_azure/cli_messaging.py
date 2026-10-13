"""The Azure CLI's messaging resources (and an ARM template's, read the same way: properties flattened), normalized to
the attribute names of the matching hashicorp/azurerm resources (inventory reads stream carriers and sending
identities from them). Pure.

  az servicebus queue list          Microsoft.ServiceBus/namespaces/queues -> azurerm_servicebus_queue
  az servicebus topic list          Microsoft.ServiceBus/namespaces/topics -> azurerm_servicebus_topic
  az eventhubs eventhub list        Microsoft.EventHub/namespaces/eventhubs -> azurerm_eventhub
  az eventgrid topic list           Microsoft.EventGrid/topics -> azurerm_eventgrid_topic (with its tags; the
                                    namespaces' child entities carry none)
  az communication email domain     Microsoft.Communication/emailServices/domains ->
    list                            azurerm_email_communication_service_domain: how it is managed and the DNS records
                                    its verification names (verificationRecords' DKIM, DKIM2, SPF, DMARC, Domain)
None of these list outputs holds a key or connection string (those are separate commands, never called).
"""
from .cli_items import flattened

STREAMS = {"microsoft.servicebus/namespaces/queues": "azurerm_servicebus_queue",
           "microsoft.servicebus/namespaces/topics": "azurerm_servicebus_topic",
           "microsoft.eventhub/namespaces/eventhubs": "azurerm_eventhub",
           "microsoft.eventgrid/topics": "azurerm_eventgrid_topic"}
DOMAINS = "microsoft.communication/emailservices/domains"
READ = (*STREAMS, DOMAINS)       # what an ARM template's reader reads of these


def _records(verification):
    """verificationRecords ({DKIM: {type, name, value, ttl}, ...}) as azurerm's verification_records block."""
    if not isinstance(verification, dict):
        return []
    return [{str(k).lower(): [{f: r.get(f) for f in ("type", "name", "value", "ttl")}]
             for k, r in verification.items() if isinstance(r, dict)}]


def messaging_items(items):
    """(azurerm type, attributes) pairs of the queues, topics, event hubs, Event Grid topics and email domains among
    (kind, item) pairs."""
    return [*((STREAMS[k], {"id": i.get("id"), "name": i.get("name"), "tags": i.get("tags") or {}})
              for k, i in items if k in STREAMS),
            *(("azurerm_email_communication_service_domain", {
                "id": d.get("id"), "name": d.get("name"), "domain_management": d.get("domainManagement"),
                "verification_records": _records(d.get("verificationRecords")), "tags": d.get("tags") or {}})
              for k, i in items if k == DOMAINS for d in (flattened(i),))]
