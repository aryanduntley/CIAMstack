"""Jinja expressions as the renderers write them into templates and variables (Ansible): string literals and calls,
quoted so any text (a shell command, a path) stays one literal. Pure."""
import json


def literal(value):
    """A Jinja literal of a string, int or bool (strings double-quoted with JSON escapes, which Jinja reads alike)."""
    return json.dumps(value)


def call(name, *args, **kwargs):
    """`name(arg, ..., key=value, ...)` with every argument a literal."""
    return f"{name}({', '.join((*map(literal, args), *(f'{k}={literal(v)}' for k, v in kwargs.items())))})"


def lookup(plugin, *args, **kwargs):
    """An Ansible lookup call: lookup("plugin", arg, ..., key=value, ...)."""
    return call("lookup", plugin, *args, **kwargs)


def expression(expr):
    """An expression as a template writes it: {{ expr }}."""
    return "{{ " + expr + " }}"
