"""The captured files an environment's servers receive that say where they go (target role and deploy path), rebuilt
with its bindings: what configuration management places (Services.deployable_config)."""
from opsdir.connectors.capture import capture_changes, deployable_config
from opsdir.connectors.registry import services
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
