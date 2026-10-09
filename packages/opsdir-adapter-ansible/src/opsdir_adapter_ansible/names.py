"""Names as Ansible takes them: group and variable names are identifiers (letters, digits, underscores; not starting
with a digit). Pure."""
import re

ROOT = "ansible"
INVENTORY = f"{ROOT}/inventory"


def ansible_name(text):
    """An Ansible group or variable name for a record's name (a server role): other characters become underscores."""
    name = re.sub(r"[^A-Za-z0-9_]", "_", text)
    return f"_{name}" if name[:1].isdigit() else name
