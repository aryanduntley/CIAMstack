"""What the Ansible files opsdir renders share, for this adapter and the add-ons rendering beside it: YAML with its
do-not-edit header and lines within ansible-lint's limit (long strings folded); text from the record that Ansible
would evaluate as a template (it holds {{, {% or {#) tagged !unsafe, so Ansible takes it as written; a requirements
file pinning what the rendered files name; a secret read at run time on the controller (its scheme owner's native
lookup, else a pipe to the scheme's resolver command); an appliance add-on's inventory file (one group, each appliance
a host signing in with its recorded login, the password read at run time). Pure."""
from opsdir.core.directory import one, rdn_value
from opsdir.core.environment import UNBOUND
from opsdir.core.formats import YAML
from opsdir.core.interchange import jinja
from opsdir.core.interchange.yaml_text import Tagged, dump
from opsdir.core.manifest import header
from opsdir.domains.infrastructure.appliances import appliances, login_secret
from opsdir.domains.pki.credentials import split_ref
from .requirements import requirements

WIDTH = 160                     # ansible-lint's yaml[line-length]
UNSAFE = "!unsafe"
JINJA = ("{{", "{%", "{#")      # what makes Ansible template a string
# a host the play runs for on the controller (an appliance's API): the controller's Python, where its SDK is installed
LOCAL = {"ansible_connection": "local", "ansible_python_interpreter": "{{ ansible_playbook_python }}"}


def unsafe(value):
    """value with every string in it (mapping keys aside) that Ansible would template tagged !unsafe: text from the
    record Ansible takes as is. Only those: Ansible's !unsafe re-reads a scalar's type ignoring its quotes (!unsafe
    "30" is a number, !unsafe "*" doesn't load), which a string holding {{, {% or {# can't be mistaken for."""
    if isinstance(value, str):
        return Tagged(UNSAFE, value) if any(j in value for j in JINJA) else value
    if isinstance(value, dict):
        return {k: unsafe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)) and not isinstance(value, Tagged):
        return [unsafe(v) for v in value]
    return value


def yaml_text(m, what, value):
    """A rendered YAML file of environment m: its header (what it is) and the value."""
    return header(m, what, YAML) + dump(value, indent_sequences=True, width=WIDTH)


def yaml_files(m, files):
    """{path: text} of {path: (what, value)}."""
    return {path: yaml_text(m, what, value) for path, (what, value) in files.items()}


def requirements_file(m, what, texts, stig=False):
    """A requirements file pinning the Galaxy collections texts name (and the STIG roles when stig)."""
    return yaml_text(m, what, requirements(texts, stig))


def secret_lookup(m, services, uri):
    """The {{ expression }} reading a secret reference at run time in environment m on the controller: the native
    lookup of its scheme's owner, else a pipe to the scheme's resolver command; None when it can't be read (no
    scheme, or one no installed adapter resolves)."""
    if not split_ref(uri)[0]:
        return None
    native = services.ansible_lookup(m, uri)
    if native:
        return jinja.expression(native)
    try:
        command = services.secret_command(uri)
    except SystemExit:          # no installed adapter resolves the scheme: secret_command says so by exiting
        return None
    return jinja.expression(jinja.lookup("ansible.builtin.pipe", command))


def login(m, services, appliance):
    """(user, password) an appliance signs in with: its ciamLoginName (tagged unsafe) and its login secret read at run
    time; UNBOUND:<what to record> for what the record lacks."""
    secret = login_secret(m, appliance)
    password = secret_lookup(m, services, secret) if secret else None
    name = rdn_value(appliance)
    return (unsafe(one(appliance, "ciamLoginName") or f"{UNBOUND}{name}-login"),
            password or f"{UNBOUND}{one(appliance, 'ciamLoginSecretRole') or name + '-login-secret'}")


def appliance_inventory(m, stack_role, group, host):
    """An appliance add-on's inventory: group, each of environment m's appliances filling stack_role a host by its
    record name, host(appliance) its variables."""
    return {"all": {"children": {group: {"hosts": {rdn_value(a): host(a) for a in appliances(m, stack_role)}}}}}
