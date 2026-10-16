"""Web access domain vocabulary: where protected web applications, their path resources and the access rules they
apply live, and the neutral terms an access gateway's or agent's policy is written in, whatever product enforces it.

  ou=protected-applications
    cn=<application>                ciamProtectedApp, its path resources below it (cn=<resource>,cn=<application>)
    ou=access-rules  cn=<rule>      ciamAccessRule (shared: several applications and resources apply one rule)
"""
from ...core.naming import branch

PROTECTED_APPS = branch("protected-applications")
ACCESS_RULES = branch("access-rules", PROTECTED_APPS)

# How users sign in to an application: through an identity service as an OpenID Connect relying party (oidc), with a
# bearer token an API client presents (token), with credentials the enforcement point collects itself (a form, HTTP
# basic, a client certificate), through a federation journey of its own (federated), the operator's own code (custom),
# or not at all (none)
SIGN_ONS = ("oidc", "token", "form", "basic", "certificate", "federated", "custom", "none")
REDIRECTED = ("oidc",)                             # sign-on through an identity service the record holds
COLLECTED = ("form", "basic", "certificate", "federated", "custom")    # sign-on the enforcement point does itself
# How a resource's patterns match the path below the application's base path: prefix (the path starts with it),
# wildcard ('*' any run of characters, '/' included), regex (a regular expression over the path)
MATCH_KINDS = ("prefix", "wildcard", "regex")
HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE")
# standard: users sign in and the rules apply; anonymous: no sign-in, the rules still apply; unprotected: passed
# through, no rule applies
ACCESS_MODES = ("standard", "anonymous", "unprotected")
# What a rule does when its subjects match: admit, refuse (a refusal beats an admission), or something the neutral
# terms can't say (a product's own rule, rebuilt by hand in another product)
EFFECTS = ("allow", "deny", "custom")
RULE_MATCHES = ("any", "all")
# Who a rule is about ('<kind> <value>'; authenticated takes no value): any signed-in user, a user (DN or id), a group
# (DN or name), an LDAP filter over the user's entry, an attribute or claim of the session (<name>=<value>), an OAuth
# 2.0 scope a token carries, a client network (CIDR)
WHO_KINDS = ("authenticated", "user", "group", "filter", "attribute", "scope", "network")
WHO = "^(authenticated|(user|group|filter|attribute|scope|network) [^ ].*)$"


def app_dn(name):
    """The DN of a protected application named name."""
    return f"cn={name},{PROTECTED_APPS}"


def resource_dn(app, name):
    """The DN of a path resource of the application at DN app."""
    return f"cn={name},{app}"


def rule_dn(name):
    """The DN of an access rule named name."""
    return f"cn={name},{ACCESS_RULES}"


def who(value):
    """(kind, value) of a ciamWho value ('group cn=crew,...' -> ('group', 'cn=crew,...')); '' for authenticated."""
    kind, _, rest = value.partition(" ")
    return kind, rest
