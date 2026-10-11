"""Which binding of the record a rendered Terraform block realizes, for reading a render back (the round trip,
milestone 5.5c). Pure. opsdir's cloud renderers name each block after the binding it renders: tf_name of the binding's
name, a binding rendered as several blocks numbered _0, _1, ... Which resource types realize which kind of binding is
each cloud adapter's table ({resource type: the binding's object class}).
"""
import re

from opsdir.core.directory import rdn_value
from opsdir.core.environment import of_class
from .hcl import tf_name

_NUMBERED = re.compile(r"_\d+$")


def realized(m, classes, type_, name):
    """The binding of environment m that a resource block of type_ named name realizes: of the class classes gives the
    type, the one whose name gives the block's (tf_name), a numbered block's (_0, _1, ...) its binding's; None when the
    type isn't in classes, or there is no such binding or more than one."""
    cls, names = classes.get(type_), (name, _NUMBERED.sub("", name))
    found = tuple(b for b in (of_class(m, cls) if cls else ()) if tf_name(rdn_value(b)) in names)
    return found[0] if len(found) == 1 else None
