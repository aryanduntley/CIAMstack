"""DoD PKI adapter: DISA's DoD PKE trust bundles (DoD, ECA, JITC, WCF). Declaration-only: it renders nothing; its
exporter (export.py) turns a downloaded bundle archive into what its importer (bundle.py) reads into the core pki
domain's trust bundles, the manifest's signature verified as DISA's README instructs."""
