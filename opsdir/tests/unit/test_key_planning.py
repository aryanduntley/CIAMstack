"""Key placement in a migration plan (in memory, on the mini estate, moving alpha -> beta): HSM-only material, material
that must be carried over, and what the target's store no longer does."""
import datetime as dt

from opsdir.core.contract import PlanContext
from opsdir.core.environment import env_model
from opsdir.core.findings import findings
from opsdir.domains.pki.checks import check_credentials
import mini_estate

ALPHA_SECRET = "cn=secret-signing-key,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
CUTOVER = dt.date(2026, 12, 1)


def all_findings(alpha, beta, **credential):
    d = mini_estate.directory(mini_estate.credential_changes(alpha, beta, **credential))
    ctx = PlanContext(d, env_model(d, "alpha/prod"), env_model(d, "beta/prod"), CUTOVER, dt.date(2026, 9, 1),
                      {}, {}, ())
    return check_credentials(ctx)


def plan(alpha, beta, **credential):
    """The findings about signing-key (alpha's disk key, which no credential describes, has its own finding)."""
    f = all_findings(alpha, beta, **credential)
    return f._replace(blockers=tuple(x for x in f.blockers if "`signing-key`" in x[1]),
                      actions=tuple(x for x in f.actions if "`signing-key`" in x[1]),
                      ok=tuple(x for x in f.ok if "`signing-key`" in x))


def test_hsm_only_material_kept_in_software_by_the_target_blocks():
    f = plan({"ciamProtectionLevel": "hsm"}, {"ciamProtectionLevel": "software", "ciamMaterialFrom": ALPHA_SECRET},
             ciamHsmRequired="TRUE", ciamContinuity="per-environment")
    assert [text for _, text, _ in f.blockers] == [
        "`signing-key` must be kept in an HSM, but beta/prod keeps it in software (fake://secrets/beta/signing)."]


def test_hsm_only_material_whose_protection_the_target_doesnt_record_blocks_until_recorded():
    f = plan({"ciamProtectionLevel": "hsm"}, {"ciamMaterialFrom": ALPHA_SECRET}, ciamHsmRequired="TRUE",
             ciamContinuity="per-environment")
    assert [text for _, text, _ in f.blockers] == [
        "`signing-key` must be kept in an HSM, but beta/prod doesn't record how it protects it "
        "(fake://secrets/beta/signing): record ciamProtectionLevel (hsm, managed-hsm or external meet the "
        "requirement)."]


def test_carry_over_material_is_copied_before_cutover():
    f = plan({}, {}, ciamContinuityReason="partners trust the signing certificate")
    (area, text, _, by), = f.actions
    assert (area, by) == ("Key", CUTOVER) and not f.blockers
    assert text == ("Copy `signing-key` from fake://secrets/alpha/signing to fake://secrets/beta/signing before "
                    "cutover (partners trust the signing certificate), and record it on the target binding "
                    "(ciamMaterialFrom).")


def test_carry_over_material_recorded_as_carried_over_is_in_place():
    f = plan({}, {"ciamMaterialFrom": ALPHA_SECRET})
    assert f.ok == ("Key `signing-key` carried over from alpha/prod to beta/prod.",) and not f.actions


def test_carry_over_material_that_cant_leave_its_store_blocks():
    for credential, alpha in (({"ciamExportable": "FALSE"}, {}),
                              ({"ciamExportable": None}, {"ciamProtectionLevel": "hsm"})):
        f = plan(alpha, {}, **credential)
        assert len(f.blockers) == 1 and "can't leave alpha/prod's store" in f.blockers[0][1]


def test_per_environment_material_needs_nothing_carried():
    assert plan({}, {}, ciamContinuity="per-environment") == findings()


def test_a_target_store_that_drops_automatic_rotation_or_replicas_is_an_action():
    f = plan({"ciamAutoRotate": "TRUE", "ciamReplicaRegion": ("r2", "r3")},
             {"ciamAutoRotate": "FALSE", "ciamReplicaRegion": "r2"}, ciamContinuity="per-environment")
    assert [text for _, text, _, _ in f.actions] == [
        "`signing-key` loses automatic rotation and replicas (2 regions in alpha/prod, 1 in beta/prod) in beta/prod "
        "(fake://secrets/beta/signing): configure the store to match, or record why not."]


def test_nothing_to_check_when_either_environment_does_not_bind_the_role():
    assert plan({}, None) == plan(None, {}) == findings()


def test_material_the_source_holds_that_no_credential_describes_is_an_action():
    (area, text, _, _), = all_findings(None, None).actions
    assert (area, text) == ("Key", "`disk-encryption` holds key material in alpha/prod (fake://keys/alpha) but no "
                                   "credential describes it, so whether beta/prod needs the same material or its own "
                                   "is unknown. Describe it under ou=credentials.")


def test_material_recorded_as_carried_over_from_another_role_blocks():
    other = "cn=key-disk,ou=bindings,env=prod,cloud=alpha,ou=environments,dc=ciam-ops"
    (_, text, _), = plan({}, {"ciamMaterialFrom": other}).blockers
    assert "carried over from `" + other + "`, which holds `disk-encryption`" in text
