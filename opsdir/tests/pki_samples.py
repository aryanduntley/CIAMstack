"""A CA certificate recorded as PEM, for the tests of what reads one (core pki.pem, a cluster gateway's backend CA
bundle): a real certificate (synthetic, its key discarded when it was made, the showcase's internal CA)."""
import base64

CERTIFICATES = "ou=certificates,dc=ciam-ops"
CA_PEM = ("-----BEGIN CERTIFICATE-----\n"
          "MIIBtDCCAVugAwIBAgIUdFFI9hcMy8nfm+SAnjZMqhhfDuYwCgYIKoZIzj0EAwIw\n"
          "KDEmMCQGA1UEAwwdRXhhbXBsZSBBZXJvIENJQU0gSW50ZXJuYWwgQ0EwHhcNMjYw\n"
          "MTE1MDAwMDAwWhcNMzEwMTE1MDAwMDAwWjAoMSYwJAYDVQQDDB1FeGFtcGxlIEFl\n"
          "cm8gQ0lBTSBJbnRlcm5hbCBDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFuk\n"
          "ceCbj6dsVm05/SKplTxvf91fajLcKAt+l+VUNyvBhiFp1zzunPDfl8MJuJDMvXw/\n"
          "6devbWx25K7B6+8zIaqjYzBhMB0GA1UdDgQWBBSrZ9vMly7Mpiou6jznd3CshN/D\n"
          "fjAfBgNVHSMEGDAWgBSrZ9vMly7Mpiou6jznd3CshN/DfjAPBgNVHRMBAf8EBTAD\n"
          "AQH/MA4GA1UdDwEB/wQEAwIBBjAKBggqhkjOPQQDAgNHADBEAiAaXitzJFy+mPmo\n"
          "BBHCWj8mb2YM+89p6Gpuas28NIh6RQIgfmcpV/B24yL5bhlmHcBfalG/tZwoya2H\n"
          "Rk0OrpXT1sQ=\n"
          "-----END CERTIFICATE-----\n")
CA_FINGERPRINT = ("0B:14:B8:72:FF:36:A5:B2:AC:98:55:00:91:C7:EA:FA:B9:B7:C0:C1:5A:78:44:09:12:35:C6:32:7A:71:1E:"
                  "8C")


def ca_records(cn="internal-ca", pem=CA_PEM, fingerprint=CA_FINGERPRINT):
    """LDIF records: the certificates branch and a CA certificate entry (with its PEM when pem is given)."""
    pem_line = f"ciamCertificatePem:: {base64.b64encode(pem.encode()).decode()}\n" if pem else ""
    return (f"dn: {CERTIFICATES}\nobjectClass: top\nobjectClass: organizationalUnit\nou: certificates\n",
            f"dn: cn={cn},{CERTIFICATES}\nobjectClass: top\nobjectClass: ciamObject\nobjectClass: ciamCertificate\n"
            f"cn: {cn}\nciamFingerprint: {fingerprint}\nciamNotAfter: 20310115000000Z\nciamCertPurpose: ca\n{pem_line}")
