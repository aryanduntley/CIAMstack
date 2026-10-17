"""EJBCA adapter: Keyfactor EJBCA (Community and Enterprise) read into the record's PKI (the core pki domain's
certification authorities, CA-scoped certificate templates, revocation endpoints and issued-certificate inventories),
metadata only. Declaration-only: it renders nothing; its importer reads the REST API's answers (inventory.py,
profiles.py), which its collector reads with a client certificate (collect.py)."""
