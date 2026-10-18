"""The HAProxy add-on's render: ansible/files/haproxy.cfg, the client CA bundles of the edge trust policies its
frontends check (ansible/files/trust/<policy>.pem: public certificates, no header: PEM has no comments, their MANIFEST
entries record them), the play ansible/haproxy.yml and what it needs from Galaxy (ansible/requirements-haproxy.yml:
the posix collection, the key lookup's), with their headers. Pure."""
from opsdir.core.manifest import header
from opsdir_adapter_ansible.output import requirements_file, yaml_text
from .client_certificates import trust_files
from .config import haproxy_cfg
from .format import FORMAT
from .playbook import play


def render(m, services):
    """{path: text} of environment m's HAProxy files."""
    playbook = yaml_text(m, "Applies the HAProxy configuration on the load-balancer servers", play(m, services))
    return {"ansible/files/haproxy.cfg": header(m, "HAProxy in front of the service names", FORMAT)
            + haproxy_cfg(m, services.endpoints),
            **{f"ansible/files/trust/{name}": pem for name, pem in trust_files(m, services.endpoints).items()},
            "ansible/haproxy.yml": playbook,
            "ansible/requirements-haproxy.yml": requirements_file(m, "Galaxy collections the HAProxy play needs, "
                                                                  "pinned", (playbook,))}
