"""Where SiteMinder's own entries live: ou=siteminder, a branch per kind, each object named after its SiteMinder name;
the source objects it carries under ou=siteminder,ou=source-objects."""
from opsdir.core.naming import branch
from opsdir.domains.automation.pipelines import slug
from opsdir.domains.federation.naming import IDENTITY_SERVICES
from opsdir.domains.governance.naming import SOURCE_OBJECTS

PRODUCT = "SiteMinder"                     # the product, as the adapter's products and ciamProductVersion name it
POLICY_SERVER, AGENT, ACCESS_GATEWAY = "sm-policy-server", "sm-agent", "sm-access-gateway"
SERVER_ROLES = (POLICY_SERVER, AGENT, ACCESS_GATEWAY)     # ciamServerRole / ciamTargetRole values it defines
SITEMINDER = branch("siteminder")
DOMAINS = branch("domains", SITEMINDER)
AUTH_SCHEMES = branch("auth-schemes", SITEMINDER)
USER_DIRECTORIES = branch("user-directories", SITEMINDER)
AGENTS = branch("agents", SITEMINDER)
CARRIED = branch("siteminder", SOURCE_OBJECTS)            # its source objects
SERVICE = f"cn=siteminder,{IDENTITY_SERVICES}"           # its own federation service, when the record has none


def name_of(text):
    """A SiteMinder name as an entry name: lower case, anything but letters, digits, '.', '_' and '-' as '-'."""
    return slug(text).lower()


def named(base, name):
    return f"cn={name},{base}"
