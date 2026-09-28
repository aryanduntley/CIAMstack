"""Federation domain vocabulary: its branches."""
from ...core.naming import branch

INTEGRATIONS = branch("integrations")            # applications and partners we federate with
IDENTITY_SERVICES = branch("identity-services")  # the platform's own identity provider / OpenID provider
