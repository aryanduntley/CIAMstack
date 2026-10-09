"""The HAProxy add-on's render: ansible/files/haproxy.cfg and the play ansible/haproxy.yml, with their headers. Pure."""
from opsdir.core.formats import YAML
from opsdir.core.interchange.yaml_text import dump
from opsdir.core.manifest import header
from .config import haproxy_cfg
from .format import FORMAT
from .playbook import play


def render(m, services):
    """{path: text} of environment m's HAProxy files."""
    return {"ansible/files/haproxy.cfg": header(m, "HAProxy in front of the service names", FORMAT)
            + haproxy_cfg(m, services.endpoints),
            "ansible/haproxy.yml": header(m, "Applies the HAProxy configuration on the load-balancer servers", YAML)
            + dump(play(m, services), indent_sequences=True)}
