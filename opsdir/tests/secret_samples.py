"""Values that are secret material (with the pattern each must trip) and values that must pass, shared by the unit
tests of the scanner and the integration tests of the store's guard (Python and PostgreSQL must agree)."""

SECRETS = (
    ("-----BEGIN RSA PRIVATE KEY-----", "private-key"),
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "private-key"),
    ("ldaps://cn=admin:hunter22@ds.example.test:1636", "url-credentials"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "jwt"),
    ("db.password=changeit", "secret-assignment"),
    ("API_KEY = 'a8f3kq29x'", "secret-assignment"),
    ('{"client_secret": "abcd1234xyz"}', "secret-field"),
    ("Authorization: Basic YWRtaW46aHVudGVyMg==", "bearer-credentials"),
    ("{SSHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=", "ldap-password-hash"),
    ("{PBKDF2-HMAC-SHA256}10000:abcdefghijklmnop", "ldap-password-hash"),
    ("key AKIAIOSFODNN7EXAMPLE in the pipeline", "aws-access-key-id"),
    ("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "aws-secret-access-key"),
    ("DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH==",
     "azure-storage-key"),
    ("https://x.blob.core.windows.net/c?sv=2022-11-02&sig=abcdefghijklmnopqrstuvwx%3D", "azure-sas-signature"),
    ("VAULT_TOKEN=hvs.CAESIJ1abcdefghijklmnopqrstuv", "vault-token"),
    ("pf.admin.pwd=OBF:JWE:eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0", "pingfederate-obfuscated"),
)

CLEAN = (
    "vault://kv/ciam/pf-admin",
    "aws-sm://ciam/prod/ds-deployment-password",
    "password = ${DS_PASSWORD}",
    '"password": "{{ vault_pf_admin }}"',
    "Admin password: rotated quarterly by the platform team",
    "Rotate the signing key every year",
    "https://sso.example-aero.test/idp",
    "ldaps://ldap.id.example-aero.test:1636",
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "secret-ref attributes are references",
    "AKIA is the prefix of AWS access key ids",
)
