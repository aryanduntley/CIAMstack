"""HAProxy's configuration format as opsdir knows it (# comments): registered under the entry point group
opsdir.formats."""
from opsdir.core.contract import Format

FORMAT = Format(name="haproxy-cfg", title="HAProxy configuration", media_type="text/plain", extensions=(),
                comment=("#",), read=None, write=None, codec=None)
