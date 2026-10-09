"""The HAProxy play: on the hosts of server role load-balancer, the TLS bundle of each terminating frontend (the
certificate's recorded PEM, then its key read at run time from the environment's binding of the certificate's key
role: never written in a file opsdir renders), haproxy.cfg checked by `haproxy -c` before it replaces the running one,
and HAProxy enabled and reloaded. A bundle the record can't complete stops the play, naming what to record. Pure."""
from opsdir.core.directory import get, one, rdn_value
from opsdir.core.environment import of_class, one_role
from opsdir.core.interchange import jinja
from opsdir.domains.edge.resolve import service_edge
from opsdir.domains.pki.pem import certificate_pem
from opsdir_adapter_ansible.names import ansible_name
from .config import CERTS

HOSTS = "load-balancer"          # the server role HAProxy runs on (and the stack role it fills)


def _bundle(m, services, svc):
    """({name, cert, key} or None, what's missing or None) of a terminating service name's TLS bundle."""
    cert = get(m.d, one(svc, "ciamTlsCertificate")) if one(svc, "ciamTlsCertificate") else None
    pem = certificate_pem(cert)
    key_role = one(cert, "ciamKeyRole") if cert is not None else None
    key = one(one_role(m, key_role), "ciamRefUri") if key_role and one_role(m, key_role) is not None else None
    if pem is None or key is None:
        return None, (f"{rdn_value(svc)}: " + ("no certificate (ciamTlsCertificate) with its PEM recorded"
                                                if pem is None else f"no binding of key role {key_role} in {m.label}"))
    return {"name": rdn_value(svc), "cert": pem, "key": jinja.expression(services.ansible_lookup(m, key))}, None


def play(m, services):
    """The HAProxy playbook (a list of one play) for environment m."""
    found = [_bundle(m, services, svc) for svc in of_class(m, "ciamServiceName")
             if (spec := service_edge(m, svc, services.endpoints)) is not None and spec.layer7]
    return [{"name": "HAProxy in front of the service names (opsdir)", "hosts": ansible_name(HOSTS), "become": True,
             "vars": {"ciam_haproxy_bundles": [b for b, _ in found if b],
                      "ciam_haproxy_missing": [why for _, why in found if why]},
             "tasks": [
                 {"name": "TLS bundles the record can't complete", "ansible.builtin.assert":
                  {"that": "ciam_haproxy_missing | length == 0",
                   "fail_msg": "Record: {{ ciam_haproxy_missing | join('; ') }}"}},
                 {"name": "TLS bundle folder", "ansible.builtin.file":
                  {"path": CERTS, "state": "directory", "mode": "0700"}},
                 {"name": "TLS bundles (certificate, then its key read at run time)", "ansible.builtin.copy":
                  {"dest": f"{CERTS}/{{{{ item.name }}}}.pem", "content": "{{ item.cert }}{{ item.key }}\n",
                   "mode": "0600"},
                  "loop": "{{ ciam_haproxy_bundles }}", "loop_control": {"label": "{{ item.name }}"},
                  "no_log": True, "notify": "Reload HAProxy"},
                 {"name": "HAProxy configuration, checked before it replaces the running one", "ansible.builtin.copy":
                  {"src": "haproxy.cfg", "dest": "/etc/haproxy/haproxy.cfg", "mode": "0644",
                   "validate": "haproxy -c -f %s"}, "notify": "Reload HAProxy"},
                 {"name": "HAProxy enabled and running", "ansible.builtin.systemd_service":
                  {"name": "haproxy", "enabled": True, "state": "started"}}],
             "handlers": [{"name": "Reload HAProxy", "ansible.builtin.systemd_service":
                           {"name": "haproxy", "state": "reloaded"}}]}]
