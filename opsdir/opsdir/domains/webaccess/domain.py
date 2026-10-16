"""Web access domain: the web applications access gateways and agents protect, in neutral terms (their paths, the
role enforcing them, sign-on and sessions, the headers they trust, their resources and access rules), whatever
product enforces them. Products project onto it from their own importers and render from it what they take over."""
from ...core.contract import Domain, directory_report
from .apps import PROTECTED_APP_HEADERS, protected_app_rows
from .checks import check_protected_apps
from .schema import FRAGMENT

DOMAIN = Domain(name="webaccess", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"protected-applications": directory_report(PROTECTED_APP_HEADERS, protected_app_rows)},
                checks=(check_protected_apps,), order=65, vocabulary={})
