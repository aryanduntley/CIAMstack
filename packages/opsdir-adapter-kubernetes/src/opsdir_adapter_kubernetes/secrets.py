"""Kubernetes secrets: k8s-secret://<namespace>/<secret>/<key> references resolved at run time with kubectl."""


def secret_command(rest):
    """The shell command printing one key of a Kubernetes secret (its data is base64; dots in a key are escaped for
    JSONPath)."""
    namespace, name, key = rest.split("/", 2)
    path = key.replace(".", "\\.")
    return f"kubectl get secret -n '{namespace}' '{name}' -o jsonpath='{{.data.{path}}}' | base64 -d"
