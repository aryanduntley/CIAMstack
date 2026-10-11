"""What changes between PingAM releases (contract.VersionChange; milestone 86), from the vendor's release notes
(research 2402): what the record holds that each change touches, so the planner names it when a move upgrades
AM. Pure."""
from opsdir.core.contract import VersionChange
from opsdir.core.directory import one, rdn_of, subtree
from opsdir.domains.configuration.record import touching_files
from .naming import JOURNEYS, POLICY_SETS
from .realms import SERVER_ROLES

# Amster export folders (one per entity type) of the authentication chains and modules AM 8 no longer has
CHAINS_AND_MODULES = r"^am/realms/[^/]+/(AuthenticationChains|\w+Module)/"
AUDIT = r"^am/(global|realms/[^/]+)/Audit\w*/"
CERTIFICATE_NODES = ("CertificateCollectorNode", "CertificateValidationNode")


def _ours(role):
    return role in SERVER_ROLES


def _nodes(d, types=None):
    return tuple(n for n in subtree(d, JOURNEYS, "pingamNode") if types is None or one(n, "pingamNodeType") in types)


def _journey_node(n):
    return f"{rdn_of(n.dn.split(',', 1)[1])}/{one(n, 'pingamDisplayName') or one(n, 'pingamNodeType')}"


def journeys(d, m, role):
    """The journeys the record holds (their nodes carry versions from AM 8.1)."""
    return tuple(one(j, "cn") for j in subtree(d, JOURNEYS, "pingamJourney")) if _ours(role) else ()


def certificate_nodes(d, m, role):
    """The journeys' certificate collector and validation nodes (journey/node)."""
    return tuple(_journey_node(n) for n in _nodes(d, CERTIFICATE_NODES)) if _ours(role) else ()


def module_instance_conditions(d, m, role):
    """The policies whose conditions include "Authentication by Module Instance" (condition type AuthScheme)."""
    return tuple(f"{rdn_of(p.dn.split(',', 1)[1])}/{one(p, 'cn')}" for p in subtree(d, POLICY_SETS, "pingamPolicy")
                 if '"AuthScheme"' in (one(p, "pingamPolicyConfig") or "")) if _ours(role) else ()


VERSION_CHANGES = (
    VersionChange(">=8.0", "authentication chains and modules are removed (8.0 can re-enable them over REST only, "
                  "8.1 not at all)", "captured Amster chain and module entities", "blocker",
                  "Rebuild each chain as a journey and its modules as nodes, import the journeys, and drop the "
                  "captured chain and module entities before the cutover.",
                  touching_files(CHAINS_AND_MODULES, SERVER_ROLES)),
    VersionChange(">=8.0", "the embedded configuration and identity store is removed", "AM's configuration, core "
                  "token and identity stores", "info", "Its stores must be external directory servers (the record's "
                  "ds roles)."),
    VersionChange(">=8.0", "the legacy audit event handler is removed", "captured audit logging configuration",
                  "action", "Replace any legacy handler with a supported one (JSON, Syslog, JMS, ...) in the "
                  "captured audit configuration.", touching_files(AUDIT, SERVER_ROLES)),
    VersionChange(">=8.1", "journey nodes carry versions (Amster exports versioned node folders)", "journeys and "
                  "their nodes", "info", "The render writes each node's version for 8.1; capture the target's export "
                  "again after the cutover so the record holds the versions AM assigned.", journeys),
    VersionChange(">=8.1", "the \"Authentication by Module Instance\" policy condition is deprecated and evaluates "
                  "to false", "policies with an AuthScheme condition", "action", "Replace the condition (a journey "
                  "or session property condition) or the policies deny what they allowed.",
                  module_instance_conditions),
    VersionChange(">=8.1", "the certificate collector and validation nodes validate the full chain by default",
                  "journeys with certificate nodes", "action", "Make sure the trust store holds each client "
                  "certificate's issuing chain, or set the nodes to validate the leaf only.", certificate_nodes),
)
