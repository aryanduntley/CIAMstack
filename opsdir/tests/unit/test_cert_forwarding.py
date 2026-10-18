"""Services.cert_forwarding (task 578, 590): the adapters that apply to an environment are asked in turn, so a cloud
whose own balancer doesn't front a service name leaves it to an on-prem load balancer the stack declares."""
from types import SimpleNamespace

from opsdir.connectors.registry import cert_forwarding_of
from opsdir.core.contract import CertForwarding

ALB = CertForwarding("X-Amzn-Mtls-Clientcert-Leaf", "url-pem", "leaf", ("10.0.1.0/24",))
F5 = CertForwarding("X-SSL-Client-Cert", "der-base64", "leaf", ("10.9.0.5/32",))


def _adapter(answer, applies=True):
    return SimpleNamespace(cert_forwarding=lambda m, svc: answer, applies=lambda m: applies)


def test_the_first_adapter_that_answers_is_taken():
    assert cert_forwarding_of(None, None, (_adapter(ALB), _adapter(F5))) == ALB


def test_a_cloud_that_doesnt_front_the_service_leaves_it_to_the_next():
    assert cert_forwarding_of(None, None, (_adapter(None), _adapter(F5))) == F5


def test_adapters_that_dont_apply_or_declare_nothing_are_skipped():
    silent = SimpleNamespace(cert_forwarding=None, applies=lambda m: True)
    assert cert_forwarding_of(None, None, (_adapter(ALB, applies=False), silent, _adapter(None))) is None
