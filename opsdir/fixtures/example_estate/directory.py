"""Directory fixture data: user-attribute records (25-user-schema), declared server configuration
(30-config-declared), observed snapshots with planted drift (50-config-observed), consumers found in access
logs (55-consumers) and ACIs (60-acis)."""
from .common import ACI, AWS, CON, DECL, OBS, PEOPLE, US, USERS, chg, ou, owner, spec, t, ua

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
INDEXES = (("uid", ["equality", "presence"], None), ("mail", ["equality"], "2026-06-14"),
           ("companyId", ["equality"], None), ("registrationStatus", ["equality"], None),
           ("lastLoginTime", ["ordering"], None), ("soldToAccount", ["equality"], None),
           ("appEntitlement", ["equality"], None))
POLICIES = (("customers", "PBKDF2-HMAC-SHA256", 5, "15 m", 5, None, "customers"),
            ("suppliers", "PBKDF2-HMAC-SHA256", 5, "15 m", 8, "365 d", "suppliers"),
            ("service-accounts", "PBKDF2-HMAC-SHA512", 0, None, 0, None, None))
HANDLERS = (("LDAPS", "TRUE", 1636), ("LDAP", "FALSE", 1389), ("HTTPS", "TRUE", 8443))
# server → planted deviations of its observed snapshot
SNAPSHOTS = (("ds-1", {}),
             ("ds-2", {"drop": ("mail",)}),
             ("ds-3", {"extra_index": ("description", ["substring"], None),
                       "overrides": {("lockout", "customers"): 10}}))
CONSUMERS = (
    ("pf-ds-svc", "uid=pf-svc,ou=service-accounts", ["10.20.4.0/24", "10.20.5.0/24"],
     "bind 61%, search 38%, modify 1%", ["uid", "mail", "givenName", "sn", "companyId", "appEntitlement", "registrationStatus"],
     0, "TRUE", 850, "2024-01-03", "ciam-platform", "critical", "tested"),
    ("customer-portal-svc", "uid=portal-svc,ou=service-accounts", ["10.30.8.0/24"],
     "search 70%, modify 25%, add 5%", ["mail", "registrationStatus", "telephoneNumber", "companyId", "challengeAnswer"],
     0, "TRUE", 120, "2023-05-17", "customer-portal-team", "critical", "tested"),
    ("supplier-portal-svc", "uid=supplier-svc,ou=service-accounts", ["10.31.2.0/24"],
     "search 88%, modify 12%", ["mail", "companyId", "soldToAccount"],
     0, "TRUE", 60, "2023-11-02", "supplier-portal-team", "high", "contacted"),
    ("mro-batch-export", "uid=mro-export,ou=service-accounts", ["10.40.12.0/24"],
     "search 100% (nightly 02:00-02:40 UTC)", ["mail", "companyId", "soldToAccount", "exportScreeningStatus", "description"],
     14, "TRUE", 40, "2024-08-20", "mro-analytics-team", "medium", "identified"),
    ("legacy-rptuser", "uid=rptuser,ou=customers,ou=people", ["10.40.7.22/32"],
     "search 100%, filter (objectClass=*) over ou=people", ["uid", "mail", "givenName", "sn", "telephoneNumber",
                                                             "challengeAnswer", "exportScreeningStatus"],
     96, "FALSE", 5, "2021-03-09", None, None, "unknown"),
    ("idm-sync", "uid=idm-sync,ou=service-accounts", ["10.20.6.0/24"],
     "search 55%, modify 45%", ["uid", "mail", "companyId", "appEntitlement", "registrationStatus", "lastLoginTime"],
     0, "TRUE", 200, "2024-01-03", "ciam-platform", "high", "tested"),
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


def user_attributes():
    return tuple(spec("25-user-schema", f"cn={name},{US}", ["top", "ciamUserAttribute"], cn=name, ciamLdapName=name,
                      ciamPiiClass=pii, ciamExportControlled=export, ciamPurpose=purpose)
                 for name, pii, export, purpose in USER_ATTRIBUTES)


def config_tree(file, base, overrides=None, drop=(), extra_index=None):
    """Declared config (base = DECL), or an observed snapshot of it with deviations."""
    lockouts = overrides or {}
    declared = base == DECL
    bdn = f"cn=userData,ou=backends,{base}"
    indexes = (*INDEXES, *((extra_index,) if extra_index else ()))
    return (*(() if declared else (ou(file, "backends", base), ou(file, "password-policies", base))),
            spec(file, bdn, ["top", "ciamBackend"], cn="userData", ciamBackendType="je", ciamBaseDn=USERS),
            *(spec(file, f"cn={name},{bdn}", ["top", "ciamIndex"], cn=name, ciamIndexedAttribute=ua(name)[0],
                   ciamIndexType=types, ciamLastChanged=t(changed) if (changed and declared) else None,
                   ciamChangeRef=chg("CHG-0931") if (name == "mail" and declared) else None)
              for name, types, changed in indexes if name not in drop),
            *(spec(file, f"cn={name},ou=password-policies,{base}", ["top", "ciamPasswordPolicy"], cn=name,
                   ciamStorageScheme=scheme, ciamLockoutFailureCount=lockouts.get(("lockout", name), lock),
                   ciamLockoutDuration=dur, ciamPasswordHistoryCount=hist, ciamMaxPasswordAge=age, ciamPopulation=pop)
              for name, scheme, lock, dur, hist, age, pop in POLICIES))


def declared_config():
    file = "30-config-declared"
    return (*(ou(file, name, DECL) for name in ("backends", "password-policies", "connection-handlers",
                                                "log-publishers", "replication")),
            *config_tree(file, DECL),
            *(spec(file, f"cn={name},ou=connection-handlers,{DECL}", ["top", "ciamConnectionHandler"], cn=name,
                   ciamEnabled=enabled, ciamListenPort=port) for name, enabled, port in HANDLERS),
            spec(file, f"cn=Json File-Based Access Logger,ou=log-publishers,{DECL}", ["top", "ciamLogPublisher"],
                 cn="Json File-Based Access Logger", ciamEnabled="TRUE"),
            spec(file, f"cn=topology,ou=replication,{DECL}", ["top", "ciamReplicationTopology"], cn="topology",
                 ciamReplicaCount=3, ciamReplicationPurgeDelay="3 d", ciamOwner=owner("ciam-platform")))


def _snapshot(srv, deviations):
    snap = f"snap={srv}-20260920,{OBS}"
    return (spec("50-config-observed", snap, ["top", "ciamSnapshot"], snap=f"{srv}-20260920",
                 ciamServerRef=f"cn={srv},{AWS}", ciamCapturedAt=t("2026-09-20", "030000")),
            *config_tree("50-config-observed", snap, **deviations))


def observed_config():
    return tuple(s for srv, deviations in SNAPSHOTS for s in _snapshot(srv, deviations))


def consumers():
    return tuple(spec("55-consumers", f"cn={cn},{CON}", ["top", "ciamConsumer"], cn=cn, ciamBindDn=f"{bind},{USERS}",
                      ciamObservedSource=src, ciamOperationMix=mix, ciamSubtreeRead=PEOPLE, ciamAttrRead=ua(*attrs),
                      ciamUnindexedSearchesPerDay=unidx, ciamTlsOnly=tls, ciamPeakOpsPerSec=peak,
                      ciamFirstSeen=t(first), ciamLastSeen=t("2026-09-22"), ciamOwner=owner(own) if own else None,
                      ciamCriticality=crit, ciamMigrationStatus=status)
                 for cn, bind, src, mix, attrs, unidx, tls, peak, first, own, crit, status in CONSUMERS)


def acis():
    return tuple(spec("60-acis", f"cn={cn},{ACI}", ["top", "ciamAci"], cn=cn, ciamAciTargetDn=PEOPLE,
                      ciamAciGrantee=f"cn={grantee},{CON}", ciamAciTargetAttr=ua(*attrs) if attrs else None,
                      ciamAciAllAttributes=None if attrs else "TRUE", ciamAciRight=rights, ciamJustification=just,
                      ciamReviewedOn=t(reviewed) if reviewed else None, ciamOwner=owner(own) if own else None,
                      ciamChangeRef=chg(ch) if ch else None)
                 for cn, grantee, attrs, rights, just, reviewed, own, ch in ACIS)
