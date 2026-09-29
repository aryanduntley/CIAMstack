"""HashiCorp Vault adapter: a secret store usable from any environment; it renders nothing itself."""
from opsdir.core.contract import Adapter
from .secrets import SECRET_PATTERNS, kv_command


def applies(m):
    """A secret store renders nothing for an environment; it only resolves vault:// references."""
    return False


ADAPTER = Adapter(name="hashicorp-vault", kind="secret-store", applies=applies, required_roles=(),
                  render_neutral=None, render_env=None, checks=(), ref_schemes=("vault",),
                  secret_schemes={"vault": kv_command}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(),
                  products=(),
                  secret_patterns=SECRET_PATTERNS)
