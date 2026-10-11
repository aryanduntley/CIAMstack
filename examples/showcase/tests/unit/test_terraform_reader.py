"""The Terraform reader against everything the cloud adapters render: every golden cloud .tf (pingfederate/'s
provider Terraform is laid out by another writer) reads completely, and block() writes each top-level block back
from what was read byte for byte, so the read data is exactly what the renderers wrote; each root (a folder's files)
builds a state read_state reads (5.5c)."""
from itertools import groupby

import pytest

from opsdir_format_terraform.hcl import TfBlock, block
from opsdir_format_terraform.hcl_reader import read_hcl
from opsdir_format_terraform.state import read_state
from opsdir_format_terraform.state_builder import tf_state
from showcase_support import GOLDEN

FILES = sorted(p for p in GOLDEN.glob("render-*/**/*.tf") if "pingfederate" not in p.parts)
ROOTS = {folder: tuple(b for p in paths for b in read_hcl(p.read_text()) if isinstance(b, TfBlock))
         for folder, paths in groupby(FILES, key=lambda p: p.parent)}


def _written_blocks(text):
    """The text of each top-level block as the file holds it: from a line opening a block to the next '}' line."""
    starts = [i for i, ln in enumerate(text.split("\n")) if ln and ln[0] not in "# }" and ln.endswith("{")]
    lines = text.split("\n")
    return ["\n".join(lines[s:lines.index("}", s) + 1]) for s in starts]


def test_the_cloud_renders_are_there():
    assert len(FILES) > 20 and {p.parts[-3] for p in FILES if p.parent.name == "terraform"}


@pytest.mark.parametrize("path", FILES, ids=lambda p: str(p.relative_to(GOLDEN)))
def test_every_block_reads_back_as_written(path):
    text = path.read_text()
    blocks = [b for b in read_hcl(text) if isinstance(b, TfBlock)]
    assert [block(b.kind, b.labels, b.body) for b in blocks] == _written_blocks(text)


@pytest.mark.parametrize("folder", ROOTS, ids=lambda p: str(p.relative_to(GOLDEN)))
def test_every_root_builds_a_state(folder):
    blocks = ROOTS[folder]
    counts = [next((v for k, v in b.body if k == "count"), 1) for b in blocks if b.kind in ("resource", "data")]
    resources, problem = read_state(tf_state(blocks)[0])
    assert (problem, len(resources)) == (None, sum(counts))
