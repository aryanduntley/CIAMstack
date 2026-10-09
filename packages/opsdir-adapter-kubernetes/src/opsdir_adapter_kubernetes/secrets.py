"""Kubernetes secrets: k8s-secret://<namespace>/<secret>/<key> references resolved at run time with kubectl."""
from opsdir.core.interchange import jinja



def secret_command(rest):
    """The shell command printing one key of a Kubernetes secret (its data is base64; dots in a key are escaped for
    JSONPath)."""
    namespace, name, key = rest.split("/", 2)
    path = key.replace(".", "\\.")
    return f"kubectl get secret -n '{namespace}' '{name}' -o jsonpath='{{.data.{path}}}' | base64 -d"


def secret_lookup(m, store, rest):
    """The Ansible lookup reading one key of a Kubernetes secret at run time (kubernetes.core.k8s, base64-decoded),
    with the controller's kubeconfig as kubectl uses it."""
    namespace, name, key = rest.split("/", 2)
    return (f"({jinja.lookup('kubernetes.core.k8s', kind='Secret', namespace=namespace, resource_name=name)}"
            f".data[{jinja.literal(key)}] | b64decode)")
