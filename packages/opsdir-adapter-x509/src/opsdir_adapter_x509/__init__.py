"""X.509 adapter: the standards themselves (RFC 5280 CRLs, RFC 6960 OCSP), CA-neutral. Declaration-only: it renders
nothing; its collector observes every recorded CA's revocation endpoints read-only (collect.py, plan.py) and its
importer checks what they answered against the CA certificates the record holds (revocation.py, verify.py) into the
core pki domain's revocation observations; its certificates importer reads what the record's certificates say of
themselves from their PEMs and recognises the cross-certificates among them (record.py, certificates.py)."""
