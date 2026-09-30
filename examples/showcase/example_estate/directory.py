"""Directory fixture data: the user directory's schema records (25-user-schema), declared server configuration
(30-config-declared), what operators know about the consumers found in access logs (55-consumers) and ACIs
(60-acis); and the production
directory servers' own configuration files (exports/ds-config: each server's config.ldif, as PingDS writes it, with
the planted drift, and an archived configuration), which the demo imports as observed snapshots."""
from opsdir.core.interchange.ldif import write_entry

from .common import ACI, CON, DECL, PEOPLE, US, USERS, chg, ou, owner, spec, t, ua

USER_ATTRIBUTES = (
    ("uid", "low", None, "Login identifier (the user's email address)"),
    ("mail", "moderate", None, "Contact and login email"),
    ("givenName", "low", None, "Display name"),
    ("sn", "low", None, "Display name"),
    ("telephoneNumber", "moderate", None, "Account recovery and support contact"),
    ("companyId", "none", None, "Link to the customer / supplier organization record"),
    ("soldToAccount", "low", None, "Commercial account for aftermarket entitlements"),
    ("registrationStatus", "none", None, "Registration workflow state (pending / approved / active / disabled)"),
    ("exportScreeningStatus", "high", "TRUE", "Result of restricted-party / export screening from the authoritative system"),
    ("challengeAnswer", "high", None, "Legacy knowledge-based recovery answers; candidate for retirement"),
    ("lastLoginTime", "low", None, "Inactivity detection for lifecycle cleanup"),
    ("appEntitlement", "low", None, "Application entitlements (app:role)"),
    ("description", "low", None, "Free text; used by a legacy export for account notes"),
)
# Definitions of the attributes no standard provides: name → (OID, syntax, equality, substring, ordering, single).
# OIDs under the RFC 5612 documentation PEN (sub-arc 2 = this fictional estate's user schema).
ARC = "1.3.6.1.4.1.32473.2"
STRING, GTIME = "1.3.6.1.4.1.1466.115.121.1.15", "1.3.6.1.4.1.1466.115.121.1.24"
DEFINITIONS = {
    "companyId": (f"{ARC}.1.1", STRING, "caseIgnoreMatch", None, None, "TRUE"),
    "soldToAccount": (f"{ARC}.1.2", STRING, "caseIgnoreMatch", None, None, None),
    "registrationStatus": (f"{ARC}.1.3", STRING, "caseIgnoreMatch", None, None, "TRUE"),
    "exportScreeningStatus": (f"{ARC}.1.4", STRING, "caseIgnoreMatch", None, None, "TRUE"),
    "challengeAnswer": (f"{ARC}.1.5", STRING, "caseExactMatch", None, None, None),
    "lastLoginTime": (f"{ARC}.1.6", GTIME, "generalizedTimeMatch", None, "generalizedTimeOrderingMatch", "TRUE"),
    "appEntitlement": (f"{ARC}.1.7", STRING, "caseIgnoreMatch", "caseIgnoreSubstringsMatch", None, None),
}
# User object classes: (name, kind, OID or None for a standard class, superclass, MAY attributes, purpose)
USER_CLASSES = (
    ("inetOrgPerson", "structural", None, None, (), "Structural class of every user entry"),
    ("exampleAeroPerson", "auxiliary", f"{ARC}.2.1", "top", tuple(DEFINITIONS),
     "Customer / supplier attributes added to every user entry"),
)
INDEXES = (("uid", ["equality", "presence"], None), ("mail", ["equality"], "2026-06-14"),
           ("companyId", ["equality"], None), ("registrationStatus", ["equality"], None),
           ("lastLoginTime", ["ordering"], None), ("soldToAccount", ["equality"], None),
           ("appEntitlement", ["equality"], None))
# (name, storage scheme, lockout count, lockout duration, history, max age, population); the first two every server
# has from setup (declared so their settings are recorded; dsconfig sets them rather than creating them)
POLICIES = (("Default Password Policy", "PBKDF2-HMAC-SHA256", None, None, None, None, None),
            ("Root Password Policy", "PBKDF2-HMAC-SHA256", None, None, None, None, None),
            ("customers", "PBKDF2-HMAC-SHA256", 5, "15 m", 5, None, "customers"),
            ("suppliers", "PBKDF2-HMAC-SHA256", 5, "15 m", 8, "365 d", "suppliers"),
            ("service-accounts", "PBKDF2-HMAC-SHA512", 0, None, 0, None, None))
HANDLERS = (("LDAPS", "TRUE", 1636), ("LDAP", "FALSE", 1389), ("HTTPS", "TRUE", 8443), ("LDIF", "FALSE", None))
PUBLISHERS = (("Json File-Based Access Logger", "TRUE"), ("File-Based Error Logger", "TRUE"),
              ("File-Based Debug Logger", "FALSE"))
# production directory servers → planted deviations of the configuration they run (the demo imports them)
SERVERS = (("ds-1", "ds-1.aws.internal.example-aero.test", {}),
           ("ds-2", "ds-2.aws.internal.example-aero.test", {"drop": ("mail",)}),
           ("ds-3", "ds-3.aws.internal.example-aero.test", {"extra_index": ("description", ["substring"], None),
                                                             "overrides": {("lockout", "customers"): 10}}))
# ds-2 before the unrecorded change behind INC-2231: the server archived its configuration then
ARCHIVED = (("ds-2", "20260912224000Z", {}),)
# what operators know about each consumer: (name, bind DN under the user directory, first seen, owner, criticality,
# migration status, last reviewed); what it does is observed from the access logs (access_logs.py, imported)
CONSUMERS = (
    ("pf-ds-svc", "uid=pf-svc,ou=service-accounts", "2024-01-03", "ciam-platform", "critical", "tested", "2026-03-02"),
    ("customer-portal-svc", "uid=portal-svc,ou=service-accounts", "2023-05-17", "customer-portal-team", "critical",
     "tested", "2025-06-10"),
    ("supplier-portal-svc", "uid=supplier-svc,ou=service-accounts", "2023-11-02", "supplier-portal-team", "high",
     "contacted", "2026-01-15"),
    ("mro-batch-export", "uid=mro-export,ou=service-accounts", "2024-08-20", "mro-analytics-team", "medium",
     "identified", None),
    ("legacy-rptuser", "uid=rptuser,ou=customers,ou=people", "2021-03-09", None, None, "unknown", None),
    ("idm-sync", "uid=idm-sync,ou=service-accounts", "2024-01-03", "ciam-platform", "high", "tested", "2026-03-02"),
)
ACIS = (
    ("aci-pf-read", "pf-ds-svc", ["uid", "mail", "givenName", "sn", "companyId", "appEntitlement", "registrationStatus"],
     ["read", "search", "compare"], "PingFederate reads profile attributes to build assertions and tokens",
     "2026-03-02", "ciam-platform", "CHG-0877"),
    ("aci-portal-write", "customer-portal-svc", ["mail", "registrationStatus", "telephoneNumber", "challengeAnswer"],
     ["read", "search", "write"], "Customer portal registration and profile management", "2026-03-02",
     "customer-portal-team", None),
    ("aci-supplier-read", "supplier-portal-svc", ["mail", "companyId", "soldToAccount"], ["read", "search"],
     "Supplier portal account lookup", "2026-03-02", "supplier-portal-team", None),
    ("aci-mro-read", "mro-batch-export", ["mail", "companyId", "soldToAccount", "exportScreeningStatus", "description"],
     ["read", "search"], "Nightly aftermarket entitlement reconciliation", "2025-09-11", "mro-analytics-team", None),
    ("aci-legacy-all", "legacy-rptuser", None, ["read", "search"], None, None, None, None),
    ("aci-idm-write", "idm-sync", ["uid", "mail", "companyId", "appEntitlement", "registrationStatus", "lastLoginTime"],
     ["read", "search", "write"], "Identity sync from the registration workflow", "2026-03-02", "ciam-platform", None),
)


def _definition(name):
    oid, syntax, eq, sub, order, single = DEFINITIONS.get(name, (None,) * 6)
    return dict(ciamLdapOid=oid, ciamLdapSyntax=syntax, ciamLdapEquality=eq, ciamLdapSubstring=sub,
                ciamLdapOrdering=order, ciamLdapSingleValue=single)


def user_attributes():
    return tuple(spec("25-user-schema", f"cn={name},{US}", ["top", "ciamUserAttribute"], cn=name, ciamLdapName=name,
                      ciamPiiClass=pii, ciamExportControlled=export, ciamPurpose=purpose, **_definition(name))
                 for name, pii, export, purpose in USER_ATTRIBUTES)


def user_classes():
    return tuple(spec("25-user-schema", f"cn={name},{US}", ["top", "ciamUserObjectClass"], cn=name, ciamLdapName=name,
                      ciamLdapClassKind=kind, ciamLdapOid=oid, ciamLdapSuperior=sup, ciamLdapMay=ua(*may) or None,
                      ciamPurpose=purpose)
                 for name, kind, oid, sup, may, purpose in USER_CLASSES)


def config_tree(file, base):
    """The declared configuration's backend, indexes and password policies."""
    bdn = f"cn=userData,ou=backends,{base}"
    return (spec(file, bdn, ["top", "ciamBackend"], cn="userData", ciamBackendType="je", ciamBaseDn=USERS),
            *(spec(file, f"cn={name},{bdn}", ["top", "ciamIndex"], cn=name, ciamIndexedAttribute=ua(name)[0],
                   ciamIndexType=types, ciamLastChanged=t(changed) if changed else None,
                   ciamChangeRef=chg("CHG-0931") if name == "mail" else None)
              for name, types, changed in INDEXES),
            *(spec(file, f"cn={name},ou=password-policies,{base}", ["top", "ciamPasswordPolicy"], cn=name,
                   ciamStorageScheme=scheme, ciamLockoutFailureCount=lock, ciamLockoutDuration=dur,
                   ciamPasswordHistoryCount=hist, ciamMaxPasswordAge=age, ciamPopulation=pop)
              for name, scheme, lock, dur, hist, age, pop in POLICIES))


def declared_config():
    file = "30-config-declared"
    return (*(ou(file, name, DECL) for name in ("backends", "password-policies", "connection-handlers",
                                                "log-publishers", "replication")),
            *config_tree(file, DECL),
            *(spec(file, f"cn={name},ou=connection-handlers,{DECL}", ["top", "ciamConnectionHandler"], cn=name,
                   ciamEnabled=enabled, ciamListenPort=port) for name, enabled, port in HANDLERS),
            *(spec(file, f"cn={name},ou=log-publishers,{DECL}", ["top", "ciamLogPublisher"], cn=name,
                   ciamEnabled=enabled) for name, enabled in PUBLISHERS),
            spec(file, f"cn=topology,ou=replication,{DECL}", ["top", "ciamReplicationTopology"], cn="topology",
                 ciamReplicaCount=3, ciamReplicationPurgeDelay="3 d", ciamOwner=owner("ciam-platform")))


# ------------------------------------------------------------------ what the servers run: their config.ldif
CFG = "cn=config"
BACKENDS = f"cn=Backends,{CFG}"


def _cfg(dn, classes, **attrs):
    return dn, ("top", *classes), {k.replace("_", "-"): v if isinstance(v, (list, tuple)) else [v]
                                   for k, v in attrs.items() if v is not None}


def _server_entries(server, drop=(), extra_index=None, overrides=None):
    """A PingDS server's cn=config tree (the parts the record models, and the product's own around them)."""
    lockouts = overrides or {}
    user_data = f"ds-cfg-backend-id=userData,{BACKENDS}"
    indexes = (*((n, types) for n, types, _ in INDEXES if n not in drop), *((extra_index[:2],) if extra_index else ()),
               ("aci", ["presence"]), ("objectClass", ["equality"]), ("entryUUID", ["equality"]))
    internal = (("rootUser", "ds-cfg-ldif-backend", "uid=admin"), ("schema", "ds-cfg-schema-backend", "cn=schema"),
                ("tasks", "ds-cfg-task-backend", "cn=tasks"), ("monitor", "ds-cfg-monitor-backend", "cn=monitor"),
                ("adminRoot", "ds-cfg-ldif-backend", "cn=admin data"))
    return (_cfg(CFG, ("ds-cfg-root-config",), cn="config", ds_cfg_server_id=server),
            _cfg(BACKENDS, ("ds-cfg-branch",), cn="Backends"),
            _cfg(user_data, ("ds-cfg-backend", "ds-cfg-pluggable-backend", "ds-cfg-je-backend"),
                 ds_cfg_backend_id="userData", ds_cfg_base_dn=USERS, ds_cfg_enabled="true", ds_cfg_db_directory="db",
                 ds_cfg_java_class="org.opends.server.backends.jeb.JEBackend"),
            _cfg(f"cn=Indexes,{user_data}", ("ds-cfg-branch",), cn="Indexes"),
            *(_cfg(f"ds-cfg-attribute={n},cn=Indexes,{user_data}", ("ds-cfg-backend-index",), ds_cfg_attribute=n,
                   ds_cfg_index_type=types) for n, types in indexes),
            *(_cfg(f"ds-cfg-backend-id={bid},{BACKENDS}", ("ds-cfg-backend", oc), ds_cfg_backend_id=bid,
                   ds_cfg_base_dn=base, ds_cfg_enabled="true") for bid, oc, base in internal),
            _cfg(f"cn=Password Policies,{CFG}", ("ds-cfg-branch",), cn="Password Policies"),
            *(_cfg(f"cn={name},cn=Password Policies,{CFG}", ("ds-cfg-authentication-policy", "ds-cfg-password-policy"),
                   cn=name, ds_cfg_java_class="org.opends.server.core.PasswordPolicyFactory",
                   ds_cfg_password_attribute="userPassword",
                   ds_cfg_default_password_storage_scheme=f"cn={scheme},cn=Password Storage Schemes,{CFG}",
                   ds_cfg_lockout_failure_count=None if lock is None else str(lockouts.get(("lockout", name), lock)),
                   ds_cfg_lockout_duration=dur, ds_cfg_password_history_count=None if hist is None else str(hist),
                   ds_cfg_max_password_age=age)
              for name, scheme, lock, dur, hist, age, _ in POLICIES),
            _cfg(f"cn=Connection Handlers,{CFG}", ("ds-cfg-branch",), cn="Connection Handlers"),
            *(_cfg(f"cn={name},cn=Connection Handlers,{CFG}", ("ds-cfg-connection-handler",), cn=name,
                   ds_cfg_enabled=enabled.lower(), ds_cfg_listen_port=None if port is None else str(port),
                   ds_cfg_use_ssl="true" if name == "LDAPS" else None) for name, enabled, port in HANDLERS),
            _cfg(f"cn=Loggers,{CFG}", ("ds-cfg-branch",), cn="Loggers"),
            *(_cfg(f"cn={name},cn=Loggers,{CFG}", ("ds-cfg-log-publisher",), cn=name, ds_cfg_enabled=enabled.lower())
              for name, enabled in PUBLISHERS))


def _config_ldif(server, deviations):
    return "".join(write_entry(dn, classes, attrs) + "\n" for dn, classes, attrs in _server_entries(server,
                                                                                                    **deviations))


def server_exports():
    """{path under exports/ds-config: text}: each production directory server's config/ directory as an operator
    copies it (config.ldif; archived configurations, which the server keeps compressed, under their .gz names)."""
    hosts = {srv: host for srv, host, _ in SERVERS}
    return {**{f"{host}/config.ldif": _config_ldif(srv, dev) for srv, host, dev in SERVERS},
            **{f"{hosts[srv]}/archived-configs/config-{stamp}.gz": _config_ldif(srv, dev)
               for srv, stamp, dev in ARCHIVED}}


def consumers():
    return tuple(spec("55-consumers", f"cn={cn},{CON}", ["top", "ciamConsumer"], cn=cn, ciamBindDn=f"{bind},{USERS}",
                      ciamFirstSeen=t(first), ciamOwner=owner(own) if own else None, ciamCriticality=crit,
                      ciamMigrationStatus=status, ciamReviewedOn=t(reviewed) if reviewed else None)
                 for cn, bind, first, own, crit, status, reviewed in CONSUMERS)


def acis():
    return tuple(spec("60-acis", f"cn={cn},{ACI}", ["top", "ciamAci"], cn=cn, ciamAciTargetDn=PEOPLE,
                      ciamAciGrantee=f"cn={grantee},{CON}", ciamAciTargetAttr=ua(*attrs) if attrs else None,
                      ciamAciAllAttributes=None if attrs else "TRUE", ciamAciRight=rights, ciamJustification=just,
                      ciamReviewedOn=t(reviewed) if reviewed else None, ciamOwner=owner(own) if own else None,
                      ciamChangeRef=chg(ch) if ch else None)
                 for cn, grantee, attrs, rights, just, reviewed, own, ch in ACIS)
