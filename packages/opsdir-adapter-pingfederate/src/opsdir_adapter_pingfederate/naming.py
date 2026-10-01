"""Where PingFederate's own entries live: ou=pingfederate, a branch per kind, each object named by its id."""
from opsdir.core.naming import branch

PINGFEDERATE = branch("pingfederate")
DATA_STORES = branch("data-stores", PINGFEDERATE)


def named(base, name):
    return f"cn={name},{base}"
