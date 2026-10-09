"""The F5 add-on's render: the AS3 declaration (ansible/f5/as3.json), its play (ansible/f5-bigip.yml), the BIG-IPs'
inventory file (ansible/inventory/f5-bigip.yml) and what the play needs from Galaxy, with their headers (the JSON
declaration has none: its MANIFEST entry records it). Pure."""
import json

from opsdir.core.directory import one
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from opsdir.domains.infrastructure.appliances import appliances
from opsdir_adapter_ansible.requirements import requirements
from .as3 import declaration, tenant
from .play import DECLARATION, STACK_ROLE, inventory, play


def render(m, services):
    """{path: text} of environment m's F5 files."""
    first = next(iter(appliances(m, STACK_ROLE)), None)
    yamls = {"ansible/f5-bigip.yml": ("Deploys the service names' AS3 declaration to the BIG-IPs",
                                      play(tenant(m, first))),
             "ansible/inventory/f5-bigip.yml": ("The BIG-IPs (load-balancer appliances)", inventory(m, services))}
    texts = {p: header(m, what, YAML) + dump(v, indent_sequences=True) for p, (what, v) in yamls.items()}
    needs = requirements(texts.values(), False)
    return {**texts, f"ansible/{DECLARATION}": json.dumps(declaration(m, services.endpoints, first), indent=2) + "\n",
            "ansible/requirements-f5-bigip.yml": header(m, "Galaxy collections the F5 play needs, pinned", YAML)
            + dump(needs, indent_sequences=True)}
