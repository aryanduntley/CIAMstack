"""How the products' logs reach an environment's Elastic data streams (decision on task 555, replacing task 552's
action notes): the Fleet policies Elastic Agent is enrolled in, for the log files on servers (fleet) and the container
output on Kubernetes (kubernetes), and the render notes of what they leave to the Elastic team. Pure: composes them.
"""
from .fleet import server_notes, server_policies
from .kubernetes import container_notes, container_policies


def fleet_policies(m, services):
    """(agent policies, integration policies) shipping environment m's logs to its Elastic data streams: the servers'
    log files' (fleet), then the containers' output (kubernetes)."""
    (agents, files), (clusters, containers) = server_policies(m, services), container_policies(m, services)
    return (*agents, *clusters), (*files, *containers)


def shipping_notes(m, services):
    """The render notes of how environment m's logs reach its Elastic data streams (fleet, kubernetes)."""
    return (*server_notes(m, services), *container_notes(m, services))
