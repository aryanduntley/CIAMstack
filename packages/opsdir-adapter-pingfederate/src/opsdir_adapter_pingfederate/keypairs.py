"""PingFederate's own key pairs imported from where each environment keeps their key material. Pure.

A key pair the record holds is a certificate carrying PingFederate's id for it (auxiliary class pingfedKeyPair:
pingfedKeyPairId; read from the bulk export's /keyPairs). Its key role (ciamKeyRole) names the credential that is its
key (ciamCredential with that binding role, PKI domain): the form the material takes (ciamMaterialFormat: pkcs12 or
pem) and the role of the secret holding the password that protects it (ciamPasswordRole). Each environment binds those
roles to secret references, and the import's file and password are those references (${secret:<ref>}, UNBOUND:<role>
where the environment binds none), resolved when the operator's pipeline applies them: opsdir never holds the key.

  ciamCertPurpose tls-server   POST /keyPairs/sslServer/import
  any other purpose            POST /keyPairs/signing/import

A key pair is imported once (PingFederate refuses an id it already has, which stays as it is), before the objects that
name it (connections that sign with it, token managers). Named instead of guessed: a key pair with no key role, no
credential for its key role, or PKCS#12 material with no password role (its password renders ${withheld}). PEM material
with no password role is taken as an unencrypted key (an empty password).
"""
from opsdir.core.directory import children, one
from opsdir.core.environment import secret_placeholder
from opsdir.core.jsondata import WITHHELD
from opsdir.domains.pki.credentials import credential_for_role
from opsdir.domains.pki.naming import CERTIFICATES

FORMATS = {"pkcs12": "PKCS12", "pem": "PEM"}
SSL_SERVER = "tls-server"


def key_pair_certificates(d):
    """The certificates of PingFederate's own key pairs (those carrying pingfedKeyPairId), by id."""
    return tuple(sorted((c for c in children(d, CERTIFICATES, "ciamCertificate") if one(c, "pingfedKeyPairId")),
                        key=lambda c: one(c, "pingfedKeyPairId")))


def key_pair_import(m, cert):
    """((path, body) of the import, or None; problems) of one key pair for environment m."""
    kid, role = one(cert, "pingfedKeyPairId"), one(cert, "ciamKeyRole")
    label = f"key pair {kid}"
    credential = credential_for_role(m.d, role) if role else None
    if credential is None:
        return None, ((f"{label}: its certificate names no key role (ciamKeyRole): not imported",) if not role else
                      (f"{label}: no credential records key role {role}: not imported",))
    form = one(credential, "ciamMaterialFormat")
    if form not in FORMATS:
        return None, (f"{label}: its key ({one(credential, 'cn')}) is {form or 'of no recorded format'}, not PKCS#12 "
                      "or PEM: not imported",)
    password_role = one(credential, "ciamPasswordRole")
    password = secret_placeholder(m, password_role) if password_role else (WITHHELD if form == "pkcs12" else "")
    kind = "sslServer" if one(cert, "ciamCertPurpose") == SSL_SERVER else "signing"
    body = {"id": kid, "fileData": secret_placeholder(m, role), "format": FORMATS[form], "password": password}
    return (f"/keyPairs/{kind}/import", body), \
        ((f"{label}: its PKCS#12 key ({one(credential, 'cn')}) has no password role (ciamPasswordRole): its password "
          "is withheld",) if form == "pkcs12" and not password_role else ())


def key_pair_imports(m):
    """(((path, body), ...) of every key pair's import for environment m, problems)."""
    done = tuple(key_pair_import(m, c) for c in key_pair_certificates(m.d))
    return tuple(x for x, _ in done if x), tuple(p for _, ps in done for p in ps)
