"""Certificate chains as the record holds them (core pki.chain): a certificate's issuer by its ciamIssuedBy link, else
the CA certificate whose subject is its issuer; the chain up to a self-issued root (or as far as the record holds it,
a loop ending it); and what a client is given to trust it: the recorded PEMs along the chain, an intermediate as the
anchor when no root is among them, the CA it was issued by, or nothing when its issuer isn't one the record holds."""
import base64

from opsdir.core.directory import get, rdn_value
from opsdir.core.interchange.ldif import parse
from opsdir.domains.pki.chain import issuer_chain, self_issued, trust_for
import mini_estate
from pki_samples import CA_PEM, CERTIFICATES
from support import REGISTRY, build_directory

AUTHORITIES = "ou=certificate-authorities,dc=ciam-ops"
OTHER_PEM = CA_PEM.replace("MIIBtDCC", "MIIBtDCD")             # a second certificate, as far as the bundle cares


def _cert(cn, purpose="ca", pem=None, **attrs):
    lines = "".join(f"{k}: {v}\n" for k, v in attrs.items())
    pem_line = f"ciamCertificatePem:: {base64.b64encode(pem.encode()).decode()}\n" if pem else ""
    return (f"dn: cn={cn},{CERTIFICATES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamCertificate\n"
            f"cn: {cn}\nciamFingerprint: AA:{len(cn):02X}\nciamNotAfter: 20310115000000Z\nciamCertPurpose: {purpose}\n"
            f"{lines}{pem_line}")


def _directory(*certs):
    branches = (f"dn: {CERTIFICATES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificates\n",
                f"dn: {AUTHORITIES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificate-authorities\n",
                f"dn: cn=Issuing CA,{AUTHORITIES}\nobjectClass: top\nobjectClass: ciamObject\n"
                f"objectClass: ciamCertAuthority\ncn: Issuing CA\nciamCaCertificate: cn=issuing,{CERTIFICATES}\n")
    return build_directory(REGISTRY, tuple(parse("\n".join((mini_estate.LDIF, *branches, *certs)))))


ROOT = _cert("root", ciamSubject="CN=Root CA", ciamIssuer="CN=Root CA")
ISSUING = _cert("issuing", ciamSubject="CN=Issuing CA", ciamIssuer="CN=Root CA",
                ciamIssuedBy=f"cn=root,{CERTIFICATES}")
LEAF = _cert("leaf", "tls-server", ciamSubject="CN=ldap.example.test", ciamIssuer="CN=Issuing CA")


def _leaf(d):
    return get(d, f"cn=leaf,{CERTIFICATES}")


def test_the_chain_runs_issuer_by_issuer_to_the_self_issued_root():
    d = _directory(ROOT, ISSUING, LEAF)
    assert [rdn_value(c) for c in issuer_chain(d, _leaf(d))] == ["issuing", "root"]   # by subject, then by link
    assert self_issued(get(d, f"cn=root,{CERTIFICATES}")) and not self_issued(_leaf(d))


def test_a_recorded_root_is_the_anchor_and_the_ca_is_named():
    d = _directory(_cert("root", pem=CA_PEM, ciamSubject="CN=Root CA", ciamIssuer="self-signed"), ISSUING, LEAF)
    trust = trust_for(d, _leaf(d))
    assert (trust.pem, trust.partial, rdn_value(trust.authority)) == (CA_PEM, False, "Issuing CA")


def test_every_recorded_pem_along_the_chain_is_given():
    d = _directory(_cert("root", pem=CA_PEM, ciamSubject="CN=Root CA", ciamIssuer="CN=Root CA"),
                   _cert("issuing", pem=OTHER_PEM, ciamSubject="CN=Issuing CA", ciamIssuer="CN=Root CA"), LEAF)
    assert trust_for(d, _leaf(d)).pem == OTHER_PEM + CA_PEM


def test_an_intermediate_with_no_root_recorded_as_pem_is_trusted_as_the_anchor():
    d = _directory(ROOT, _cert("issuing", pem=CA_PEM, ciamSubject="CN=Issuing CA", ciamIssuer="CN=Root CA",
                               ciamIssuedBy=f"cn=root,{CERTIFICATES}"), LEAF)
    trust = trust_for(d, _leaf(d))
    assert (trust.pem, trust.partial) == (CA_PEM, True)


def test_a_held_chain_without_any_pem_says_so():
    d = _directory(ROOT, ISSUING, LEAF)
    trust = trust_for(d, _leaf(d))
    assert (trust.pem, trust.partial, [rdn_value(c) for c in trust.chain]) == (None, False, ["issuing", "root"])


def test_an_issuer_the_record_doesnt_hold_leaves_the_runtime_to_decide():
    d = _directory(ROOT, _cert("public", "tls-server", ciamSubject="CN=sso.example.test",
                               ciamIssuer="CN=Public CA R11"))
    assert trust_for(d, get(d, f"cn=public,{CERTIFICATES}")) is None
    assert trust_for(d, None) is None


def test_a_loop_in_the_records_links_ends_the_chain():
    d = _directory(_cert("a", ciamSubject="CN=A", ciamIssuer="CN=B", ciamIssuedBy=f"cn=b,{CERTIFICATES}"),
                   _cert("b", ciamSubject="CN=B", ciamIssuer="CN=A", ciamIssuedBy=f"cn=a,{CERTIFICATES}"),
                   _cert("leaf", "tls-server", ciamIssuer="CN=A"))
    assert [rdn_value(c) for c in issuer_chain(d, _leaf(d))] == ["a", "b"]
