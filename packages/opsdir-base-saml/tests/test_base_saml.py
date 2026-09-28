"""The SAML base: a pure XML writer, standard metadata from plain values, and metadata rendered from the record."""
import xml.etree.ElementTree as ET

from opsdir.core.directory import make_directory
from opsdir.domains.federation.naming import IDENTITY_SERVICES, INTEGRATIONS
from opsdir_base_saml.metadata import MD, binding_urn, idp_descriptor, sp_descriptor
from opsdir_base_saml.render import SamlEndpoints, saml_files
from opsdir_base_saml.xmltext import Comment, document, element

NS = {"md": MD}


def test_the_writer_escapes_and_is_deterministic():
    root = element("a", (("x", 'say "hi" & <go>'), ("skip", None)), (Comment("a -- b"), element("b", text="1 < 2")))
    assert document(root) == ('<?xml version="1.0" encoding="UTF-8"?>\n<a x=\'say "hi" &amp; &lt;go&gt;\'>\n'
                              "  <!-- a - - b -->\n  <b>1 &lt; 2</b>\n</a>\n")
    assert document(element("e")).endswith("<e/>\n")


def test_sp_metadata_is_well_formed_standard_metadata():
    xml = document(sp_descriptor("https://sp.test/saml", (("HTTP-POST", "https://sp.test/acs"),), ("persistent",),
                                 ("email",), (("sp-signing", "saml-signing", "AA:BB"),), "sp"))
    sp = ET.fromstring(xml.split("\n", 1)[1]).find("md:SPSSODescriptor", NS)
    acs = sp.find("md:AssertionConsumerService", NS)
    assert (acs.get("Binding"), acs.get("Location"), acs.get("isDefault")) == (binding_urn("HTTP-POST"),
                                                                              "https://sp.test/acs", "true")
    assert sp.find("md:NameIDFormat", NS).text.endswith(":persistent")
    assert [r.get("Name") for r in sp.iter(f"{{{MD}}}RequestedAttribute")] == ["email"]
    assert "sp-signing (saml-signing) SHA-256 AA:BB" in xml


def test_idp_metadata_orders_its_elements_as_the_schema_does():
    xml = document(idp_descriptor("https://idp.test", (("HTTP-Redirect", "https://idp.test/sso"),),
                                  (("HTTP-POST", "https://idp.test/slo"),), ("transient",)))
    idp = ET.fromstring(xml.split("\n", 1)[1]).find("md:IDPSSODescriptor", NS)
    assert [c.tag.split("}")[1] for c in idp] == ["SingleLogoutService", "NameIDFormat", "SingleSignOnService"]


def _directory():
    return make_directory((), {}, (
        (f"cn=app,{INTEGRATIONS}", ("top", "ciamIntegration"),
         {"cn": ["app"], "ciamProtocolType": ["saml2-sp"], "ciamEntityId": ["https://app.test"],
          "ciamAcsUrl": ["https://app.test/acs"]}),
        (f"cn=partner,{INTEGRATIONS}", ("top", "ciamIntegration"),
         {"cn": ["partner"], "ciamProtocolType": ["saml2-idp"], "ciamEntityId": ["https://partner.test"],
          "ciamSsoUrl": ["https://partner.test/sso"]}),
        (f"cn=sso,{IDENTITY_SERVICES}", ("top", "ciamIdentityService"),
         {"cn": ["sso"], "ciamBaseUrl": ["https://sso.test/"], "ciamEntityId": ["https://sso.test/idp"]})))


def test_the_record_renders_partners_and_the_given_services_at_the_products_paths():
    d = _directory()
    files = saml_files(d, (d.entries[f"cn=sso,{IDENTITY_SERVICES}".lower()],),
                       SamlEndpoints(sso=(("HTTP-Redirect", "/sso"),), slo=()))
    assert sorted(files) == ["saml/idp/sso.xml", "saml/partner-idp/partner.xml", "saml/sp/app.xml"]
    assert 'Location="https://sso.test/sso"' in files["saml/idp/sso.xml"]
    assert binding_urn("HTTP-POST") in files["saml/sp/app.xml"]          # the default ACS binding
    assert saml_files(d, (), SamlEndpoints((), ())).keys() == {"saml/partner-idp/partner.xml", "saml/sp/app.xml"}
