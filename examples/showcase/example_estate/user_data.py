"""The production user directory's data as an ldapsearch would print it (exports/ds-data/source-prod.ldif), for
`opsdir data-profile` (a showcase and test fixture). Pure; everything is fictional and generated from each entry's
number, so the file is the same on every run.

What a data profile should find in it:
  - 23 customers migrated from the old portal, and the legacy reports account, still hold salted SHA-512 hashes
    ({SSHA512}); every password policy the record declares stores PBKDF2
  - a CRM integration nobody recorded writes crmContactId on suppliers; cn has no user-schema record either
  - the supplier approvers group still lists a supplier deleted last year
  - customers registered before 2022 still hold challenge answers (KBA)
  - idle accounts: a share of customers haven't logged in for over a year, some never
The estate's own attributes say what they mean (lastLoginTime, registrationStatus, challengeAnswer): the demo passes
them to `opsdir data-profile --term`.
"""
import datetime as dt

from opsdir.core.interchange.ldif import write_entry

from .common import PEOPLE, USERS

CUSTOMERS, SUPPLIERS = 180, 60
LEGACY_HASHED = 23                       # customers 1..23 came from the old portal
KBA_BEFORE = 37                          # customers 1..37 registered before 2022
GROUPS = f"ou=groups,{USERS}"
SERVICE_ACCOUNTS = ("pf-svc", "portal-svc", "supplier-svc", "mro-export", "idm-sync")
TERMS = ("last-login=lastLoginTime", "kba=challengeAnswer", "pending=registrationStatus=pending",
         "disabled=registrationStatus=disabled")
AS_OF = dt.date(2026, 9, 23)             # the showcase's as-of date


def _days_ago(days):
    """GeneralizedTime `days` before the showcase's as-of date, at noon."""
    return (AS_OF - dt.timedelta(days=days)).strftime("%Y%m%d") + "120000Z"


def _person(kind, n, extra):
    uid = f"{kind}-{n}"
    status = "pending" if n % 23 == 5 else "disabled" if n % 31 == 7 else "active"
    login = None if n % 11 == 0 or status == "pending" else _days_ago((n * 37) % 900)
    return (f"uid={uid},ou={kind}s,{PEOPLE}",
            ("top", "person", "organizationalPerson", "inetOrgPerson", "exampleAeroPerson"),
            {"uid": (uid,), "cn": (f"{kind.title()} {n}",), "sn": (str(n),), "givenName": (kind.title(),),
             "mail": (f"{uid}@{kind}s.example.test",),
             **({"telephoneNumber": (f"+1 555 01{n % 100:02d}",)} if n % 3 else {}),
             "companyId": (f"C{1000 + n // 4}",), "registrationStatus": (status,),
             **({"lastLoginTime": (login,)} if login else {}),
             "userPassword": (("{SSHA512}" if kind == "customer" and n <= LEGACY_HASHED
                               else "{PBKDF2-HMAC-SHA256}10000:") + "c2FsdA==:aGFzaA==",),
             "pwdChangedTime": (_days_ago((n * 53) % 1200),),
             **({"pwdAccountLockedTime": (_days_ago(1),)} if n % 47 == 3 else {}),
             "createTimestamp": (_days_ago(400 + n),), "entryUUID": (f"00000000-0000-4000-8000-{n:012d}",),
             **extra})


def _customers():
    return tuple(_person("customer", n, {**({"challengeAnswer": ("{\"q\": 1}",)} if n <= KBA_BEFORE else {}),
                                         "appEntitlement": ("portal:customer",)})
                 for n in range(1, CUSTOMERS + 1))


def _suppliers():
    return tuple(_person("supplier", n, {"soldToAccount": (f"S{2000 + n}",), "exportScreeningStatus": ("cleared",),
                                         "appEntitlement": ("supplier-portal:user",),
                                         **({"crmContactId": (f"CRM-{70000 + n}",)} if n % 3 == 0 else {})})
                 for n in range(1, SUPPLIERS + 1))


def _service_accounts():
    return tuple((f"uid={uid},ou=service-accounts,{USERS}", ("top", "account", "simpleSecurityObject"),
                  {"uid": (uid,), "userPassword": ("{PBKDF2-HMAC-SHA512}10000:c2FsdA==:aGFzaA==",)})
                 for uid in SERVICE_ACCOUNTS)


def _group(name, members):
    return (f"cn={name},{GROUPS}", ("top", "groupOfNames"), {"cn": (name,), **({"member": members} if members else {})})


def _groups():
    return (_group("customer-portal-admins", tuple(f"uid=customer-{n},ou=customers,{PEOPLE}" for n in (40, 41, 42))),
            _group("supplier-approvers", (f"uid=supplier-3,ou=suppliers,{PEOPLE}",
                                          f"uid=supplier-999,ou=suppliers,{PEOPLE}")),     # deleted in 2025
            _group("beta-testers", ()))


def _container(dn, classes, **attrs):
    return dn, classes, {k: (v,) for k, v in attrs.items()}


def entries():
    """(dn, object classes, {attribute: values}) of every entry, in the order ldapsearch prints them."""
    return (_container(USERS, ("top", "domain"), dc="partners"),
            _container(PEOPLE, ("top", "organizationalUnit"), ou="people"),
            _container(f"ou=customers,{PEOPLE}", ("top", "organizationalUnit"), ou="customers"),
            *_customers(),
            # the legacy reports account binds as a person (it is a consumer of the directory)
            (f"uid=rptuser,ou=customers,{PEOPLE}", ("top", "person", "organizationalPerson", "inetOrgPerson"),
             {"uid": ("rptuser",), "cn": ("Report User",), "sn": ("Reports",),
              "userPassword": ("{SSHA512}cmVwb3J0cw==",)}),
            _container(f"ou=suppliers,{PEOPLE}", ("top", "organizationalUnit"), ou="suppliers"),
            *_suppliers(),
            _container(f"ou=service-accounts,{USERS}", ("top", "organizationalUnit"), ou="service-accounts"),
            *_service_accounts(),
            _container(GROUPS, ("top", "organizationalUnit"), ou="groups"),
            *_groups())


def user_data():
    """{path under exports/: text}: the source directory's data as ldapsearch -LLL would print it (with its version
    line and search result, which the profiler skips)."""
    body = "\n".join(write_entry(dn, classes, attrs) for dn, classes, attrs in entries())
    return {"ds-data/source-prod.ldif": f"version: 1\n\n{body}\n# search result\nsearch: 2\nresult: 0 Success\n"}
