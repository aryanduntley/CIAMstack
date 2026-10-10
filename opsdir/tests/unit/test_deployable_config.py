"""The captured files an environment's servers receive that say where they go (target role and deploy path), rebuilt
with its bindings: what configuration management places (Services.deployable_config); and the files the adapters
rendering an environment hand it for its servers (Services.host_files)."""
from opsdir.connectors.capture import capture_changes, deployable_config
from opsdir.connectors.registry import host_files_of, services
from opsdir.core.contract import Adapter, HostFile
from opsdir.core.formats import JAVA_PROPERTIES
from network_fixtures import model
import mini_estate


def test_files_with_a_role_and_deploy_path_are_deployable():
    placed, _ = capture_changes(mini_estate.directory(), JAVA_PROPERTIES, "port=8443\n", "web-props",
                                "web/conf/web.properties", role="web", deploy_path="/opt/web/conf/web.properties")
    unplaced, _ = capture_changes(mini_estate.directory(), JAVA_PROPERTIES, "a=1\n", "loose", "conf/loose.properties")
    d, alpha, _ = model(changes=(*placed, *unplaced))
    assert deployable_config(d, alpha) == (("web", "/opt/web/conf/web.properties", "web/conf/web.properties",
                                            "port=8443\n"),)
    assert services().deployable_config(alpha) == deployable_config(d, alpha)


def _adapter(name, host_files):
    return Adapter(name, "provider", lambda m: True, (), None, None, (), (), {}, None, None, {}, None, (), (), (), (),
                   None, None, host_files=host_files)


def test_host_files_come_from_the_adapters_rendering_the_environment():
    d, alpha, _ = model()
    agent = HostFile("web", "/etc/agent.json", "{}\n", ("agent", "reload"))
    seen = []
    renders = _adapter(mini_estate.ADAPTER_NAME, lambda m, services: seen.append(services.logs) or (agent,))
    assert host_files_of(alpha, (renders, _adapter("undeclared", lambda m, services: (agent, agent)))) == (agent,)
    assert len(seen) == 1                                   # only the environment's declared stack's adapters
    assert host_files_of(alpha, (_adapter(mini_estate.ADAPTER_NAME, None),)) == ()
    assert agent.mode == "0644"
