"""The F5 add-on's render: an AS3 declaration per tenant (ansible/f5/as3-<tenant>.json), the play deploying them
(ansible/f5-bigip.yml), the BIG-IPs' inventory file (ansible/inventory/f5-bigip.yml) and what the play needs from
Galaxy, with their headers (the JSON declarations have none: their MANIFEST entries record them). Pure."""
import json

from opsdir_adapter_ansible.output import requirements_file, yaml_files
from .as3 import applications, declaration
from .play import declaration_path, inventory, play, tenants


def render(m, services):
    """{path: text} of environment m's F5 files."""
    found = tenants(m)
    has_applications = bool(applications(m, services.endpoints))
    texts = yaml_files(m, {
        "ansible/f5-bigip.yml": ("Deploys the service names' AS3 declaration to the BIG-IPs, one request per tenant "
                                 "(check first: --tags dry-run)", [play(t, has_applications) for t in found]),
        "ansible/inventory/f5-bigip.yml": ("The BIG-IPs (load-balancer appliances), by tenant",
                                           inventory(m, services))})
    declarations = {f"ansible/{declaration_path(t)}": json.dumps(declaration(m, services.endpoints, a[0]), indent=2)
                    + "\n" for t, a in found.items() if has_applications}
    return {**texts, **declarations,
            "ansible/requirements-f5-bigip.yml": requirements_file(m, "Galaxy collections the F5 play needs, pinned",
                                                                   texts.values())}
