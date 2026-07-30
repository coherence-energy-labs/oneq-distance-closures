"""The Negative Claim Admission Contract must be able to say NO.

Seven times this program shipped a green that was testing nothing, each found
separately as though it were a new kind of mistake. The shape was always the
same: a negative or completeness claim emitted with no machine-consulted object
proving the question had been posed.

These tests pin the abstraction that generalizes all seven. Every one asserts a
REFUSAL, plus the control that an honest claim is still admitted -- because a
contract that refuses everything is exactly as useless as one that admits
everything, and considerably more smug.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "src"))

from oneq.coverage import SpectrumCompleteness, assess    # noqa: E402


def test_full_coverage_is_admitted():
    """The control."""
    v = assess(question="q", required=["a", "b", "c"], executed=["a", "b", "c"])
    assert v.coverage_complete and v.negative_claim_admissible
    assert not v.omitted_partitions


def test_a_missing_partition_refuses_the_claim():
    v = assess(question="q", required=["a", "b", "c"], executed=["a", "c"])
    assert not v.negative_claim_admissible
    assert v.omitted_partitions == ("b",)
    assert "never ran" in v.reason


def test_an_unexercised_anchor_refuses_the_claim():
    """SAT's defect: two anchor classes required, one decided, UNSAT returned."""
    v = assess(question="q", required=["x"], executed=["x"],
               anchors_required=["block1", "block2"],
               anchors_exercised=["block1"])
    assert not v.negative_claim_admissible
    assert v.anchors_missing == ("block2",)


def test_an_empty_schedule_cannot_support_a_negative_claim():
    """Nothing required, nothing run, nothing proved.

    Without this, `assess(required=[], executed=[])` would compute an empty set
    difference and report complete coverage of nothing -- the `all([])` vacuity
    that has already cost this program two retractions.
    """
    v = assess(question="q", required=[], executed=[])
    assert not v.coverage_complete and not v.negative_claim_admissible
    assert "empty schedule" in v.reason


def test_a_domain_that_cannot_contain_the_target_refuses_despite_full_coverage():
    """The mutation-corpus and G3 defect, abstracted.

    Every partition ran; the domain simply never held an instance of what was
    being looked for. Coverage is complete and the claim is still worthless.
    """
    v = assess(question="q", required=["a", "b"], executed=["a", "b"],
               corpus_can_trigger_target=False)
    assert v.coverage_complete, "coverage genuinely was complete"
    assert not v.negative_claim_admissible, "but the question was never posed"
    assert "never posed" in v.reason


def test_admissibility_cannot_be_asserted_only_derived():
    """There must be no way to hand `assess` the answer.

    `multiplicity_is_complete` was a bare boolean a producer set to True. The
    whole point of the contract is that the only route to an admissible verdict
    is a required set and an executed set that agree.
    """
    import inspect
    params = set(inspect.signature(assess).parameters)
    for forbidden in ("coverage_complete", "negative_claim_admissible",
                      "admissible", "complete"):
        assert forbidden not in params, (
            f"assess() accepts `{forbidden}` -- the verdict can be asserted "
            "instead of derived")


# ------------------------------------------------------- spectrum completeness

def test_spectrum_below_its_own_distance_is_partial_not_complete():
    """The defect that cost the 18x headline.

    A distance-6 code whose sweep stopped at depth 3 reported a COMPLETE
    weight-6 multiplicity. Completeness needs p >= w.
    """
    s = SpectrumCompleteness(completed_depth=3, accumulator_cap=200000,
                             observed_count=96)
    assert not s.complete_for_weight(6)
    assert s.status_for_weight(6) == "partial_information_set_projection"
    assert s.complete_through_weight == 3


def test_spectrum_at_or_above_the_weight_is_complete():
    s = SpectrumCompleteness(completed_depth=6, accumulator_cap=200000,
                             observed_count=96)
    assert s.complete_for_weight(6)
    assert s.status_for_weight(6) == "complete"


def test_hitting_the_accumulator_cap_voids_completeness_at_every_weight():
    """A truncated tally is not a tally, however deep the sweep went."""
    s = SpectrumCompleteness(completed_depth=9, accumulator_cap=200000,
                             observed_count=200000)
    assert s.complete_through_weight == 0
    assert not s.complete_for_weight(1)


def test_the_completion_rule_travels_with_the_artifact():
    """A verifier must be able to re-derive the range from the stated rule,
    rather than trust the number the producer computed under it."""
    s = SpectrumCompleteness(completed_depth=6, accumulator_cap=200000,
                             observed_count=96)
    j = s.to_json(6)
    assert j["completion_rule"] == "paired_zimmermann_p_ge_w"
    assert j["complete_through_weight"] == j["completed_depth"]
    assert j["multiplicity_status"] == "complete"


@pytest.mark.parametrize("depth,weight,expect", [(3, 6, False), (6, 6, True),
                                                 (7, 6, True), (5, 6, False)])
def test_completeness_tracks_depth_against_weight(depth, weight, expect):
    s = SpectrumCompleteness(completed_depth=depth, accumulator_cap=200000,
                             observed_count=10)
    assert s.complete_for_weight(weight) is expect
