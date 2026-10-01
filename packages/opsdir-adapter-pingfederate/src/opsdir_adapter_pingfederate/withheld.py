"""What PingFederate's configuration holds that may be secret: withheld at import, rendered per environment. Pure.

Withheld whole, under its plain name, so each environment's reference renders where PingFederate takes the value:

  every encrypted value          encryptedPassword, encryptedValue, encryptedSecret, ... (as password, value, secret):
                                 PingFederate encrypts them with the deployment's own master key, so they never carry
                                 to another deployment
  a plugin field named a secret  {"name": "Secret Key", "value": ...} (a field's name says what its value holds)
  what opsdir renders in place   ${secret:<ref>}, ${withheld}, UNBOUND:<role>: a render imports back unchanged
  anything else that may be secret (registered patterns, secret-named settings, random-looking tokens)

An object's withheld values all take the reference of its one credential role (pingfedCredentialRole), set by a
change: never guessed.
"""
from opsdir.core.directory import one, values
from opsdir.core.environment import secret_placeholder
from opsdir.core.jsondata import WITHHELD, rendered_in_place, with_values, without_secrets
from opsdir.core.secrets import sensitive_name

ENCRYPTED = "$encrypted"            # a value held whole until it is withheld


def _plain_key(key):
    return key[9].lower() + key[10:] if key.startswith("encrypted") and len(key) > 9 and key[9].isupper() else key


def _secret_field(value):
    """A plugin field ({"name", "value"/"encryptedValue"}) whose name says it holds a secret, with a value."""
    return isinstance(value.get("name"), str) and sensitive_name(value["name"]) and \
        ("encryptedValue" in value or value.get("value") not in (None, ""))


def plain_values(value):
    """Settings with every encrypted value under its plain name, and every secret-named field's value, wrapped as
    encrypted (held whole until it is withheld)."""
    if isinstance(value, dict) and _secret_field(value):
        return {**{k: plain_values(v) for k, v in value.items() if k not in ("value", "encryptedValue")},
                "value": {ENCRYPTED: value.get("encryptedValue", value.get("value"))}}
    if isinstance(value, dict):
        return {_plain_key(k): ({ENCRYPTED: v} if _plain_key(k) != k else plain_values(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [plain_values(v) for v in value]
    return value


def _sealed(value):
    return rendered_in_place(value) or (isinstance(value, dict) and ENCRYPTED in value)


def withheld_settings(settings, patterns):
    """(settings with what may be secret replaced by None, JSON Pointers of what was withheld)."""
    return without_secrets(plain_values(settings), patterns, sealed=_sealed)


def filled(m, entry, settings):
    """Settings with the entry's withheld values as environment m gives them: ${secret:<ref>} of its credential role,
    UNBOUND:<role>, or ${withheld} while no credential role is set (the planner blocks on both)."""
    credential = one(entry, "pingfedCredentialRole")
    return with_values(settings, values(entry, "pingfedWithheld"),
                       secret_placeholder(m, credential) if credential else WITHHELD)
