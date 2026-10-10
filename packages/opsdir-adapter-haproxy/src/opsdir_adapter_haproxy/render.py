"""The HAProxy add-on's render: ansible/files/haproxy.cfg, the play ansible/haproxy.yml and what it needs from Galaxy
(ansible/requirements-haproxy.yml: the posix collection, the key lookup's), with their headers. Pure."""
from opsdir.core.manifest import header
from opsdir_adapter_ansible.output import requirements_file, yaml_text
from .config import haproxy_cfg
from .format import FORMAT
from .playbook import play


def render(m, services):
    """{path: text} of environment m's HAProxy files."""
    playbook = yaml_text(m, "Applies the HAProxy configuration on the load-balancer servers", play(m, services))
    return {"ansible/files/haproxy.cfg": header(m, "HAProxy in front of the service names", FORMAT)
            + haproxy_cfg(m, services.endpoints),
            "ansible/haproxy.yml": playbook,
            "ansible/requirements-haproxy.yml": requirements_file(m, "Galaxy collections the HAProxy play needs, "
                                                                  "pinned", (playbook,))}
