"""What DS-lineage servers' attributes mean to the data profile, beyond the LDAP standards: the last login time a
password policy records (its last-login-time-attribute: ds-last-login-time in PingDS's sample policies,
ds-pwp-last-login-time in older configurations; a policy naming another attribute needs it added here) and the flag an
administrator disables an account with (ds-pwp-account-disabled). Both are operational: the ldapsearch feeding
`opsdir data-profile` asks for them ("+"); the lineage's own operational attributes (ds-*, etag, the virtual
isMemberOf) aren't counted as user data. A last-login format that doesn't start with yyyyMMdd counts as
`unreadable`."""
from opsdir.domains.directory.profile import Terms

TERMS = Terms(password=(), schemes=frozenset(), last_login=("ds-last-login-time", "ds-pwp-last-login-time"),
              password_changed=(), locked=(), disabled=(("ds-pwp-account-disabled", "true"),), pending=(), kba=(),
              member=(), group_classes=(), operational=("ds-*", "etag", "isMemberOf"))
