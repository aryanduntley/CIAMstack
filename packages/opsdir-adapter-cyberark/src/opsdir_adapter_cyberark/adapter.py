"""CyberArk adapter: a privileged access management vault as a secret store usable from any environment; it renders
nothing itself."""
from opsdir.core.contract import Adapter
from .secrets import password_command


def applies(m):
    """A secret store renders nothing for an environment; it only resolves cyberark:// references."""
    return False


ADAPTER = Adapter(name="cyberark", kind="secret-store", applies=applies, required_roles=(),
                  render_neutral=None, render_env=None, checks=(), ref_schemes=("cyberark",),
                  secret_schemes={"cyberark": password_command}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(),
                  products=(),
                  secret_patterns=(), importers=(), profile_terms=None)
