"""Shell command lines from their words (core.shell): each word read back by a shell as exactly that one word, nothing
in it expanded, whatever characters it holds; and an Ansible pipe lookup keeps such a line one Jinja literal."""
import json
import shlex
import subprocess

from opsdir.core.interchange import jinja
from opsdir.core.shell import command

TEXT = "it's \"x\" $(touch made) `touch made` ${HOME} ; touch made | cat & echo \\ * ~ # done"


def test_each_word_reads_back_as_one_word():
    words = ("prog", TEXT, "", "plain", "--flag=a b", "'", '"', 7)
    assert shlex.split(command(*words)) == [str(w) for w in words]


def test_plain_words_stay_as_they_are():
    assert command("aws", "s3", "ls", "s3://bucket/key", "--output", "text") == (
        "aws s3 ls s3://bucket/key --output text")


def test_a_shell_runs_it_without_expanding_anything(tmp_path):
    done = subprocess.run(["sh", "-c", command("printf", "%s\\n", TEXT, "second")], capture_output=True, text=True,
                          cwd=tmp_path, check=True)
    assert done.stdout.splitlines() == [TEXT, "second"] and not (tmp_path / "made").exists()


def test_an_ansible_pipe_lookup_keeps_the_line_one_literal():
    line = command("fake-cli", "get", TEXT)
    expr = jinja.lookup("ansible.builtin.pipe", line)
    assert expr.startswith("lookup(") and expr.endswith(")")
    assert json.loads(f"[{expr[len('lookup('):-1]}]") == ["ansible.builtin.pipe", line]
    assert shlex.split(line) == ["fake-cli", "get", TEXT]
