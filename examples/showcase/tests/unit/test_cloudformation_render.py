"""The showcase's AWS environments rendered as CloudFormation (5.6, the aws render target cloudformation), before and
after the approved changes: every Terraform resource goes exactly one place (a template's resource, part of one, or
the Terraform root beside the template, saying why), the templates hold exactly those resources and what they expand
into, every rendered type is in the mapping, and the render declares the formats of its files."""
import pytest

from opsdir.connectors.registry import ADAPTERS, environment_specs, services
from opsdir.connectors.render import render_env, render_parts
from opsdir_adapter_aws.cfn_types import NO_NATIVE, TYPES, cloudformation_translation
from opsdir_adapter_aws.terraform import WHAT, render_files
from opsdir_format_terraform.hcl import TfBlock
from opsdir_format_terraform.translate import address, root_items, roots


def _aws(d):
    """(spec, model, Terraform files, translation) of each environment the aws adapter renders."""
    found = services(ADAPTERS)
    out = []
    for spec in environment_specs(d):
        m, adapters, _, _, _ = render_parts(d, spec)
        if any(a.name == "aws" for a in adapters):
            files = render_files(m, found)
            out.append((spec, m, files, cloudformation_translation(m, files, WHAT)))
    return tuple(out)


@pytest.fixture(scope="module", params=["before", "after"])
def translated(request, estate):
    return _aws(estate[request.param])


def test_the_showcase_renders_aws_environments(translated):
    assert {spec for spec, *_ in translated} >= {"source/prod", "source/stage"}


def test_every_rendered_type_is_mapped_or_has_no_native_form(translated):
    rendered = {b.labels[0] for _, _, files, _ in translated for root in roots(files).values()
                for b in root_items(root) if isinstance(b, TfBlock) and b.kind == "resource"}
    assert rendered - set(TYPES) - NO_NATIVE == set()


def test_every_terraform_resource_goes_exactly_one_place(translated):
    for spec, _, files, t in translated:
        for directory, root in roots(files).items():
            resources = {address(b) for b in root_items(root) if isinstance(b, TfBlock) and b.kind == "resource"}
            assert set(t.placements[directory]) == resources, (spec, directory)


def test_the_templates_hold_the_placed_resources_and_their_expansions(translated):
    for spec, _, files, t in translated:
        placed = {p.where: set() for places in t.placements.values() for p in places.values()}
        for places in t.placements.values():
            for a, p in places.items():
                if p.kind == "template":
                    placed[p.where].add((p.detail, TYPES[a.split(".")[0]].type))
        for path, template in t.templates.items():
            ids = {(r.logical_id, r.type) for r in template.resources}
            assert placed[path] <= ids, (spec, path)
            extra = {i for i, _ in ids - placed[path]}
            assert all(any(i.startswith(lid) and i != lid for lid, _ in placed[path]) for i in extra), (spec, extra)


def test_merged_resources_are_part_of_a_resource_written_natively(translated):
    for spec, _, _, t in translated:
        for places in t.placements.values():
            for a, p in places.items():
                if p.kind == "merged":
                    assert places[p.detail].kind == "template", (spec, a)


def test_what_stays_terraform_is_in_the_root_beside_the_template(translated):
    for spec, _, _, t in translated:
        for places in t.placements.values():
            for a, p in places.items():
                if p.kind == "terraform":
                    side = t.side[p.where]
                    assert any(isinstance(b, TfBlock) and address(b) == a for b in side.items), (spec, a)
                    assert f"#   {a}: {p.detail}" in side.head


def test_a_render_choosing_cloudformation_declares_its_files(estate):
    d = estate["before"]
    _, files = render_env(d, "source/prod", wanted={"aws": ("cloudformation",)})
    assert not any(p.startswith("terraform/") for p in files)
    assert "cloudformation/template.yaml" in files and "cloudformation/landing-zone/template.yaml" in files
    manifest = files["MANIFEST.json"]
    assert '"render_targets": {\n    "aws": [\n      "cloudformation"\n    ]' in manifest
    assert '"cloudformation/template.yaml": {\n      "scope": "environment-specific",\n      "format": ' \
           '"cloudformation-yaml"' in manifest
    assert '"cloudformation/landing-zone/terraform/main.tf": {\n      "scope": "landing-zone",\n      "format": "hcl"' \
        in manifest
