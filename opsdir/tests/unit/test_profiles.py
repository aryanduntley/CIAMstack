"""Product profiles (5.9): a product adapter's rendered and captured files mapped into its product's instance tree, the
render handing every product's tree to the deployment kits after the other adapters render; a secret reference turned
into a slot named by its role (the kit writes its product's own runtime substitution), never a value."""
import pytest

from opsdir.connectors.render import render_env
from opsdir.core.environment import env_model
from opsdir.core.profiles import ProductProfile, profile_tree, slot_env, slot_token, slotted
import mini_estate
from mini_estate import FAKE

ALPHA = "alpha/prod"


@pytest.fixture(scope="module")
def d():
    return mini_estate.directory()


def test_a_product_s_files_map_into_its_instance_tree():
    profile = ProductProfile("Product", (("product/conf/", "conf/"), ("files/product/", ""), ("product/", "other/")))
    files = {"product/conf/a.json": "A", "files/product/resolver/boot.properties": "B", "product/x.json": "X",
             "elsewhere/y.json": "Y"}
    assert profile_tree(profile, files) == {"conf/a.json": "A", "resolver/boot.properties": "B", "other/x.json": "X"}


def test_a_role_names_its_token_and_its_environment_variable():
    assert slot_token("pf-grants-db-password") == "opsdir.pf.grants.db.password"
    assert slot_env("pf-grants-db-password") == "OPSDIR_PF_GRANTS_DB_PASSWORD"
    assert slot_token("Hr_DB--key") == "opsdir.hr.db.key"


def test_a_secret_reference_becomes_its_role_s_slot(d):
    m = env_model(d, ALPHA)
    text, roles, unknown = slotted(m, '{"a": "${secret:fake://keys/alpha}", "b": "${secret:fake://nowhere}", '
                                      '"c": "UNBOUND:x", "d": "${secret:fake://keys/alpha}"}',
                                   lambda role: "&{" + slot_token(role) + "}")
    assert text == ('{"a": "&{opsdir.disk.encryption}", "b": "${secret:fake://nowhere}", "c": "UNBOUND:x", '
                    '"d": "&{opsdir.disk.encryption}"}')
    assert (roles, unknown) == (("disk-encryption",), ("fake://nowhere",))


def test_the_kits_render_the_products_profiles_after_every_adapter(d):
    # the environment's stack declares one adapter: here it is both the product and the kit
    product = FAKE._replace(kind="product", profile=ProductProfile("Fake", (("fake/", "conf/"),)),
                            formats=(("fake/*.txt", "text"), ("kit/*.txt", "text")))
    kit = product._replace(render_profiles=lambda m, profiles, targets: {
        "kit/profile.txt": "\n".join(f"{p}: {t}" for p, t in sorted(profiles["Fake"].items()))})
    _, files = render_env(d, ALPHA, (kit,))
    assert files["kit/profile.txt"] == ("conf/env.txt: alpha/prod: fake-cli get secrets/admin\n\n"
                                        "conf/neutral.txt: the same in every environment\n")
    assert "kit/profile.txt" not in render_env(d, ALPHA, (product,))[1]
