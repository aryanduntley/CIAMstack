"""What PingAccess's settings hold that is or may be secret: withheld at import, rendered per environment. Pure.

  a hidden field {"value", "encryptedValue"}    its value withheld (/<field>/value), the ciphertext dropped: the
                                                export encrypts secrets with the deployment's own key, so neither the
                                                value nor its ciphertext is ever stored
  a setting whose name says it holds a secret   withheld whole (sharedSecret, password, privateKey, ...)
  what opsdir renders in place                  ${secret:<ref>}, ${withheld}, UNBOUND:<role>: a render imports back
                                                unchanged
  anything else that may be secret              registered patterns, random-looking tokens (core.secrets)

The record keeps only where each was (paWithheld, JSON Pointers). An object's withheld values all take the reference of
its one credential role (paCredentialRole), set by an approved change: never guessed.
"""
from types import MappingProxyType

from opsdir.core.directory import one, values
from opsdir.core.environment import secret_placeholder
from opsdir.core.jsondata import WITHHELD, rendered_in_place, with_values, without_secrets
from opsdir.core.secrets import sensitive_name
from .api import ENCRYPTED, HIDDEN

SEALED = MappingProxyType({"$withheld": True})      # a value marked secret, until it is withheld


def _hidden(key, value):
    """Whether an object is a hidden field holding a value: its ciphertext, or a value under a secret-named setting."""
    return ENCRYPTED in value or (key is not None and sensitive_name(key) and value.get(HIDDEN) not in (None, ""))


def marked(value, key=None):
    """Settings with every secret marked SEALED: a hidden field's value (its ciphertext dropped), a secret-named
    setting's value."""
    if isinstance(value, dict) and _hidden(key, value):
        return {**{k: marked(v, k) for k, v in value.items() if k not in (ENCRYPTED, HIDDEN)}, HIDDEN: SEALED}
    if isinstance(value, dict):
        return {k: marked(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [marked(v, key) for v in value]
    if isinstance(value, str) and value and key is not None and sensitive_name(key) and not rendered_in_place(value):
        return SEALED
    return value


def _sealed(value):
    return rendered_in_place(value) or value is SEALED


def withheld_settings(settings, patterns):
    """(settings with what is or may be secret replaced by None, JSON Pointers of what was withheld)."""
    return without_secrets(marked(settings), patterns, sealed=_sealed)


def credential_value(m, entry):
    """What environment m renders for an entry's withheld values: ${secret:<ref>} of its credential role,
    UNBOUND:<role>, or ${withheld} while no credential role is set (the planner blocks on both)."""
    role = one(entry, "paCredentialRole")
    return secret_placeholder(m, role) if role else WITHHELD


def filled(m, entry, settings):
    """Settings with the entry's withheld values as environment m gives them."""
    return with_values(settings, values(entry, "paWithheld"), credential_value(m, entry))
