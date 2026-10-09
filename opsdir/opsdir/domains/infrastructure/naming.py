"""Infrastructure domain vocabulary: its branches and enumerations."""
from ...core.naming import branch

ENVIRONMENTS = branch("environments")
EXTERNAL_ALLOWLISTS = branch("external-allowlists")
EXPOSURES = ("internal", "internet")    # a service name's load balancer: private network only, or internet-facing
