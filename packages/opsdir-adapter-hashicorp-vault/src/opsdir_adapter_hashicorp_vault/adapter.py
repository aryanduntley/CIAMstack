"""HashiCorp Vault adapter: a secret store usable from any environment; it renders nothing itself, and tells the
Kubernetes renderers how the External Secrets Operator and the Secrets Store CSI driver read its references. It
inventories its key/value mounts, metadata only (inventory.py, collect.py), for reconciling the record's references
with what the store holds."""
from opsdir.core.contract import Adapter
from .collect import COLLECTORS
from .inventory import KV_METADATA_IMPORTER, locate
from .kubernetes import SECRET_DELIVERY
from .secrets import SECRET_PATTERNS, kv_command, kv_lookup


def applies(m):
    """A secret store renders nothing for an environment; it only resolves vault:// references."""
    return False


ADAPTER = Adapter(name="hashicorp-vault", kind="secret-store", applies=applies, required_roles=(),
                  render_neutral=None, render_env=None, checks=(), ref_schemes=("vault",),
                  secret_schemes={"vault": kv_command}, renders=None, neutral_label=None,
                  vocabulary={}, schema=None, formats=(),
                  products=(),
                  secret_patterns=SECRET_PATTERNS, importers=(KV_METADATA_IMPORTER,), profile_terms=None, access=None,
                  collectors=COLLECTORS, secret_delivery=SECRET_DELIVERY, ansible_lookup={"vault": kv_lookup},
                  inventory_locator={"vault": locate})
