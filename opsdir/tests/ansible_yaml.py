"""Reading rendered Ansible YAML in tests: Ansible's !unsafe tag (record text Ansible must not template) read as the
plain string it marks, every other YAML rule PyYAML's safe loader's."""
import yaml


class _Loader(yaml.SafeLoader):
    """The safe loader, taking !unsafe scalars as their strings."""


_Loader.add_constructor("!unsafe", lambda loader, node: loader.construct_scalar(node))


def load(text):
    """The value a rendered Ansible YAML text holds."""
    return yaml.load(text, _Loader)


def untagged_strings(text):
    """The string values (mapping keys aside) a rendered YAML text holds without the !unsafe tag."""
    def walk(node):
        if isinstance(node, yaml.MappingNode):
            return [s for _, v in node.value for s in walk(v)]
        if isinstance(node, yaml.SequenceNode):
            return [s for v in node.value for s in walk(v)]
        return [node.value] if node.tag == "tag:yaml.org,2002:str" else []
    return walk(yaml.compose(text, _Loader))
