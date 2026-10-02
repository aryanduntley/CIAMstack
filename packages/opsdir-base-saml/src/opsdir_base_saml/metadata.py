"""SAML 2.0 metadata (OASIS saml-metadata-2.0-os) from plain values: entity descriptors of a service provider and of
an identity provider. The standard names live here once; products and the record supply the values."""
from types import MappingProxyType

from .xmltext import Comment, element

MD = "urn:oasis:names:tc:SAML:2.0:metadata"
PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
ATTRNAME_BASIC = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
NAMEID_FORMATS = MappingProxyType({"unspecified": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
                                   "emailAddress": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                                   "persistent": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                                   "transient": "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"})
DEFAULT_ACS_BINDING = "HTTP-POST"      # the Web Browser SSO profile's usual response binding
DEFAULT_SSO_BINDING = "HTTP-Redirect"  # ... and its usual request binding


def binding_urn(binding):
    """urn:oasis:names:tc:SAML:2.0:bindings:<binding> (HTTP-POST, HTTP-Redirect, HTTP-Artifact, SOAP)."""
    return f"urn:oasis:names:tc:SAML:2.0:bindings:{binding}"


def _nameid_formats(formats):
    return tuple(element("md:NameIDFormat", text=NAMEID_FORMATS[f]) for f in formats)


def _certificates(certificates):
    """The certificates the record links, named. KeyDescriptor needs the certificate itself, which the record doesn't
    hold (it records certificate facts, never material), so they are listed for whoever adds it."""
    if not certificates:
        return ()
    return (Comment("KeyDescriptor needs the certificate itself, which the record doesn't hold. Certificates the "
                    "record links:"),
            *(Comment(f"{name} ({role or 'no key role'}) SHA-256 {fp}") for name, role, fp in certificates))


def _endpoints(tag, endpoints):
    return tuple(element(tag, (("Binding", binding_urn(b)), ("Location", url))) for b, url in endpoints)


def sp_descriptor(entity_id, acs, nameid_formats=(), requested=(), certificates=(), service_name=None):
    """EntityDescriptor of a service provider. acs: ((binding, url), ...); requested: attribute names it receives;
    certificates: ((name, key role, SHA-256 fingerprint), ...)."""
    requested_attrs = (element("md:AttributeConsumingService", (("index", "0"),), (
        element("md:ServiceName", (("xml:lang", "en"),), text=service_name or entity_id),
        *(element("md:RequestedAttribute", (("Name", n), ("NameFormat", ATTRNAME_BASIC))) for n in requested))),
    ) if requested else ()
    acs_elements = tuple(element("md:AssertionConsumerService", (("Binding", binding_urn(b)), ("Location", url),
                                                                 ("index", str(n)), ("isDefault", "true" if n == 0 else None)))
                         for n, (b, url) in enumerate(acs))
    return element("md:EntityDescriptor", (("xmlns:md", MD), ("entityID", entity_id)), (
        element("md:SPSSODescriptor", (("protocolSupportEnumeration", PROTOCOL),), (
            *_certificates(certificates), *_nameid_formats(nameid_formats), *acs_elements, *requested_attrs)),))


def idp_descriptor(entity_id, sso, slo=(), nameid_formats=(), certificates=()):
    """EntityDescriptor of an identity provider. sso, slo: ((binding, url), ...); certificates as for sp_descriptor."""
    return element("md:EntityDescriptor", (("xmlns:md", MD), ("entityID", entity_id)), (
        element("md:IDPSSODescriptor", (("WantAuthnRequestsSigned", "false"), ("protocolSupportEnumeration", PROTOCOL)), (
            *_certificates(certificates), *_endpoints("md:SingleLogoutService", slo), *_nameid_formats(nameid_formats),
            *_endpoints("md:SingleSignOnService", sso))),))
