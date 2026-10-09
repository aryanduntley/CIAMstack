"""Secret material as data: the forms it takes, and finding or redacting it in text. The store refuses any value that
matches a registered pattern (SPEC R4), so secrets are never stored, only referenced; importers and scanners redact
with the same patterns before anything reaches the record.

Patterns are regular expressions in the dialect Python and PostgreSQL share, because the store checks them itself:
no \\b or \\B (use explicit character classes), no look-around, no named groups, and (?i) only at the very start.
The core registers the generic forms; each adapter registers its vendor's (Adapter.secret_patterns).

Importers are stricter than the store, because they know more than a value: a setting's name, and a whole file's
text. A setting whose name ends in a secret word (password, secret, token, api key, ...) or whose value looks random
has its value withheld; a whole text is stored only when nothing in it raises a concern (text_concerns).
"""
import math
import re
from collections import Counter
from functools import reduce

from .contract import SecretPattern

CORE_OWNER = "opsdir"

CORE_PATTERNS = (
    SecretPattern("private-key", r"-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY( BLOCK)?-----",
                  "A private key block (PEM, OpenSSH, PGP)"),
    SecretPattern("url-credentials", r"[A-Za-z][A-Za-z0-9+.-]*://[^/?#@\s:]+:[^/?#@\s]+@",
                  "A URL carrying a user name and password"),
    SecretPattern("jwt", r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
                  "A signed token (JWT)"),
    SecretPattern("secret-assignment",
                  r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|client[_-]?secret|private[_-]?key)"
                  r"[\"']?\s*=\s*[\"']?[^\s\"'$<{%][^\s\"']{5,}",
                  "A secret assigned in configuration syntax (password=..., api_key = ...)"),
    SecretPattern("secret-field",
                  r"(?i)[\"'](password|passwd|secret|client_secret|api_key|apikey|access_key|private_key|token)[\"']"
                  r"\s*:\s*[\"'][^\"'$<{%][^\"']{5,}[\"']",
                  "A secret as a JSON or YAML field (\"password\": \"...\")"),
    SecretPattern("bearer-credentials", r"(?i)authorization:\s*(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}",
                  "HTTP Authorization credentials"),
    SecretPattern("ldap-password-hash",
                  r"(?i)\{(ssha|ssha256|ssha384|ssha512|sha|sha256|sha384|sha512|smd5|md5|crypt|bcrypt|pbkdf2"
                  r"[a-z0-9-]*|aes|3des|blowfish|rc4)\}[A-Za-z0-9+/=$.:]{8,}",
                  "A stored LDAP password (RFC 2307 {SCHEME}value)"),
)

# Constructs PostgreSQL's regular expressions don't share with Python's
_NOT_SHARED = (r"\b", r"\B", "(?=", "(?!", "(?<", "(?P", r"\A", r"\Z", r"\z")


def dialect_problems(patterns):
    """Why patterns can't be enforced by the store: not a Python regular expression, or a construct outside the shared
    dialect. Empty when every pattern is usable."""
    def problems(p):
        body = p.pattern[4:] if p.pattern.startswith("(?i)") else p.pattern
        found = [f"{p.name}: uses {c}, which the store can't evaluate" for c in _NOT_SHARED if c in body]
        found += [f"{p.name}: inline flags only as a leading (?i)"] if re.search(r"\(\?[a-zA-OQ-Z]", body) else []
        try:
            re.compile(p.pattern)
        except re.error as e:
            found.append(f"{p.name}: {e}")
        return found
    names = [p.name for p in patterns]
    return tuple([f"{n}: registered twice" for n in sorted({n for n in names if names.count(n) > 1})]
                 + [x for p in patterns for x in problems(p)])


def scan(text, patterns):
    """Names of the patterns that match somewhere in the text, in pattern order."""
    return tuple(p.name for p in patterns if re.search(p.pattern, text))


def value_findings(dn, attrs, patterns):
    """(dn, attribute, pattern name) for every attribute value of an entry that looks like secret material."""
    return tuple(dict.fromkeys((dn, attr, name) for attr, values in attrs.items() for v in values
                               for name in scan(v, patterns)))


def redact(text, patterns):
    """The text with every match replaced by [redacted: pattern name]."""
    return reduce(lambda t, p: re.sub(p.pattern, f"[redacted: {p.name}]", t), patterns, text)


# ------------------------------------------------------------------ importers: names, randomness, whole texts
_SECRET_WORDS = frozenset({"password", "passwd", "pwd", "passphrase", "secret", "token", "credential", "credentials",
                           "pin"})
_SECRET_PAIRS = frozenset({("api", "key"), ("private", "key"), ("access", "key"), ("secret", "key"),
                           ("client", "secret"), ("master", "key")})
_NOT_A_SECRET = frozenset({"", "true", "false", "yes", "no", "on", "off", "null", "none"})
_PLACEHOLDER = re.compile(r"^\s*(\$\{.*\}|\{\{.*\}\}|%[^%]+%|<[^>]*>|@[^@]+@|[a-z][a-z0-9+.-]*://\S+)\s*$", re.I)
_TOKEN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_ASSIGNMENT = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*[\"']?([^\s\"',;]+)")


def _words(name):
    """The words of a key's last segment: split at separators and camelCase, lower-cased."""
    last = re.split(r"[/|@\[\]]", name.rstrip("/]"))[-1]
    return [w.lower() for w in re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", last)]


def sensitive_name(name):
    """Whether a setting's name says it holds a secret: its last word is a secret word, or its last two words are a
    secret pair (api key, private key, client secret, ...). userPassword and admin.pwd are; passwordPolicy and
    token.lifetime are not."""
    words = _words(name)
    return bool(words) and (words[-1] in _SECRET_WORDS or tuple(words[-2:]) in _SECRET_PAIRS)


def placeholder(value):
    """Whether a value only stands in for one (empty, true/false, ${VAR}, {{ var }}, %VAR%, <value>, a URI)."""
    return value.strip().lower() in _NOT_A_SECRET or bool(_PLACEHOLDER.match(value))


def _entropy(token):
    counts = Counter(token)
    return -sum(n / len(token) * math.log2(n / len(token)) for n in counts.values())


def random_tokens(text):
    """Long tokens that look random (32+ characters mixing upper case, lower case and digits, with high entropy):
    keys, signatures and encoded secrets; hex digests and paths are not."""
    return tuple(t for t in _TOKEN.findall(text)
                 if re.search(r"[A-Z]", t) and re.search(r"[a-z]", t) and re.search(r"[0-9]", t) and _entropy(t) >= 4.0)


_CERTIFICATES = re.compile(r"^\s*(-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----\s*)+$")


def certificates_only(value):
    """Whether a value is nothing but PEM certificates: public material, however random its encoding looks."""
    return isinstance(value, str) and bool(_CERTIFICATES.match(value))


def withheld(locator, value, patterns):
    """Why a captured setting's value must not be stored (it needs a secret reference instead), or None. PEM
    certificates alone are public: never withheld for looking random (a private key is caught by the patterns)."""
    found = scan(value, patterns)
    if found:
        return f"its value looks like secret material ({', '.join(found)})"
    if sensitive_name(locator) and not placeholder(value):
        return "its name says it holds a secret"
    if random_tokens(value) and not certificates_only(value):
        return "its value looks random (a key or token)"
    return None


def _line_concerns(number, line, patterns):
    found = scan(line, patterns)
    named = [key for key, value in _ASSIGNMENT.findall(line) if sensitive_name(key) and not placeholder(value)]
    return tuple([(number, f"secret material ({', '.join(found)})")] if found else []) + \
        tuple((number, f"{key} is given a value") for key in named) + \
        tuple([(number, "a random-looking token")] if random_tokens(line) else [])


def text_concerns(text, patterns):
    """(line number, concern) for everything in a text that may be secret material: registered patterns, secret
    names given real values, random-looking tokens. A text is stored whole only when there are none."""
    return tuple(c for number, line in enumerate(text.split("\n"), 1) for c in _line_concerns(number, line, patterns))
