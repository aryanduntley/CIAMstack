"""The Kubernetes adapter as the core sees it: a registered platform adapter (it renders for environments that run
workloads on Kubernetes) that also resolves k8s-secret:// references."""
from opsdir.connectors.registry import ADAPTERS, secret_command
from opsdir_adapter_kubernetes.adapter import ADAPTER


def test_registered_through_its_entry_point():
    assert ADAPTER in ADAPTERS and ADAPTER.kind == "platform"
    assert [t[0] for t in ADAPTER.render_targets] == ["external-secrets", "csi"]


def test_resolves_one_key_of_a_secret_through_the_registry():
    assert ADAPTER.ref_schemes == ("k8s-secret",)
    assert secret_command("k8s-secret://ciam/ds-passwords/root", (ADAPTER,)) == (
        "kubectl get secret -n 'ciam' 'ds-passwords' -o jsonpath='{.data.root}' | base64 -d")


def test_dots_in_a_key_are_escaped_for_jsonpath():
    assert "jsonpath='{.data.tls\\.key}'" in secret_command("k8s-secret://ciam/ds-tls/tls.key", (ADAPTER,))
