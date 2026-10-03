"""Cloud evaluators' answers as recorded evidence: where each answer is saved and read back from, the worst part of a
permission deciding it, dated; and the script a cloud renderer writes only when the cloud has an evaluator."""
from opsdir.core.contract import AccessModel
from opsdir.domains.access.evaluations import (evaluated, evaluation_of, evaluation_path, evaluation_script,
                                               evaluations_by_identity)


def test_answers_are_saved_where_they_are_read_back_from():
    assert evaluation_path("ciam-prod-pf", "read-secret pf-admin-password") == \
        "evaluations/ciam-prod-pf/read-secret__pf-admin-password.json"
    assert evaluation_path("ciam-prod-pf", "use-key k", 2) == "evaluations/ciam-prod-pf/use-key__k.2.json"
    assert evaluation_of("aws/prod/evaluations/ciam-prod-pf/use-key__k.2.json") == ("ciam-prod-pf", "use-key k")
    assert evaluation_of("evaluations/notes.json") is None and evaluation_of("iam.json") is None


def test_a_permission_is_its_worst_part_dated_the_import():
    assert evaluated("use-key k", ("allowed", "unknown"), "x", "2026-10-02") == "use-key k: unknown (x 2026-10-02)"
    assert evaluated("use-key k", ("allowed", "denied", "unknown"), "x", None) == "use-key k: denied (x undated)"
    found = [("evaluations/a/use-key__k.1.json", "allowed"), ("evaluations/a/use-key__k.2.json", "allowed"),
             ("evaluations/b/use-key__k.json", None), ("other.json", "denied")]
    assert evaluations_by_identity(found, lambda doc: doc, "x", "2026-10-02") == {
        "a": ("use-key k: allowed (x 2026-10-02)",)}                        # not an answer, not about one: left out


def test_no_script_without_an_evaluator():
    model = AccessModel(permissions=(), escalations=(), covers=lambda g, b: False, resource=lambda b: None)
    assert model.evaluator is None and evaluation_script(None, model, "cloud") is None
