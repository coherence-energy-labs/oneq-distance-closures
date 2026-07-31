r"""The Negative Claim Admission Contract.

ONE LAW, LEARNED THE HARD WAY SEVEN TIMES:

    Coverage that is recorded but never consulted is not a guard.

Every one of these was a clean-looking green that was testing nothing, and each
was found separately, as if it were a new kind of mistake:

  * `multiplicity_is_complete` was DECLARED true rather than derived, so a
    depth-3 sweep of a distance-6 code reported a complete weight-6 tally. The
    18x multiplicity spread built on it was withdrawn.
  * SAT recorded `anchors_run` and returned UNSAT without consulting it, so
    deciding one of two anchor classes still produced an exhaustiveness claim.
  * MITM recorded `splits` and never checked them against a schedule, so a
    sweep that skipped a whole family of splits still reported "exhaustive".
  * The mutation corpus could not pose the question three mutants tested: every
    code had d=2 against lightest-stabilizer-weight 4, so deleting the
    stabilizer rejection changed nothing observable.
  * A mutant's source anchor drifted past a trailing comment and became a SKIP,
    while the gate still reported a clean sweep.
  * G3's fault injection sampled randomly into a space where the dangerous
    region has measure 2^-66, and reported perfect coverage of it.
  * C0's audited claim reported F = 1.0000 over 45,000 circuits run at d=1,
    where no stabilizer exists for the detector to fire on.

Seven instances, one shape: a NEGATIVE or COMPLETENESS claim emitted without a
machine-consulted object proving the question was actually posed.

THE CONTRACT. A negative claim is admissible only when a `CoverageVerdict` says
so, and a `CoverageVerdict` never accepts its own verdict as input -- `assess()`
DERIVES `coverage_complete` and `negative_claim_admissible` from the partitions
and anchors it is given. There is deliberately no constructor that lets a caller
assert admissibility; the one honest way to get a True is to hand over a
required set and an executed set that agree.

    verdict = assess(question="no logical of weight <= W",
                     required=schedule, executed=actually_run)
    if not verdict.negative_claim_admissible:
        return UNKNOWN(verdict.reason)     # never NOT_FOUND

THE THIRD FIELD. `corpus_can_trigger_target` covers the failure the first two
cannot see: a sweep may cover its whole declared domain and still be worthless
because the domain never contained an instance of what it was looking for. That
is what happened to the three mutants and to G3. Passing `None` means the
question was not asked; passing `False` makes the claim inadmissible no matter
how complete the coverage. A test suite that cannot fail is complete over
nothing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass(frozen=True)
class CoverageVerdict:
    """Whether a negative or completeness claim may be emitted at all.

    Frozen, and every boolean is derived by `assess`. Construct it directly only
    when deserializing an artifact you are about to re-derive anyway.
    """
    question: str
    domain_hash: str = ""
    required_partitions: tuple[str, ...] = ()
    executed_partitions: tuple[str, ...] = ()
    omitted_partitions: tuple[str, ...] = ()
    anchors_required: tuple[str, ...] = ()
    anchors_exercised: tuple[str, ...] = ()
    anchors_missing: tuple[str, ...] = ()
    corpus_can_trigger_target: bool | None = None
    coverage_complete: bool = False
    negative_claim_admissible: bool = False
    reason: str = ""

    def to_json(self) -> dict:
        d = asdict(self)
        for k, v in list(d.items()):
            if isinstance(v, tuple):
                d[k] = list(v)
        return d

    def __str__(self) -> str:
        tag = "ADMISSIBLE" if self.negative_claim_admissible else "REFUSED"
        return f"[{tag}] {self.question}: {self.reason}"


def _norm(xs) -> tuple[str, ...]:
    return tuple(str(x) for x in (xs or ()))


def assess(*, question: str,
           required, executed,
           domain_hash: str = "",
           anchors_required=(), anchors_exercised=(),
           corpus_can_trigger_target: bool | None = None) -> CoverageVerdict:
    """Derive admissibility. There is no way to assert it.

    `required` is the schedule the claim's theorem needs -- derived from the
    problem, NOT from the loop that walks it. Deriving it from the loop is how
    a skipped partition redefines "everything" instead of being caught by it.
    """
    req, exe = _norm(required), _norm(executed)
    omitted = tuple(sorted(set(req) - set(exe)))
    a_req, a_exe = _norm(anchors_required), _norm(anchors_exercised)
    a_missing = tuple(sorted(set(a_req) - set(a_exe)))

    complete = (not omitted) and (not a_missing) and bool(req or a_req)
    admissible = complete and corpus_can_trigger_target is not False

    if not req and not a_req:
        reason = ("no required partitions declared -- an empty schedule cannot "
                  "support a negative claim")
    elif omitted:
        reason = (f"{len(omitted)} of {len(req)} required partitions never ran "
                  f"({list(omitted[:4])}{'...' if len(omitted) > 4 else ''})")
    elif a_missing:
        reason = f"anchors not exercised: {list(a_missing)}"
    elif corpus_can_trigger_target is False:
        reason = ("coverage is complete over a domain that cannot contain the "
                  "target -- the question was never posed")
    else:
        reason = (f"all {len(req)} partitions executed"
                  + (f", all {len(a_req)} anchors exercised" if a_req else "")
                  + ("" if corpus_can_trigger_target is None
                     else ", and the domain can contain the target"))
    return CoverageVerdict(
        question=question, domain_hash=domain_hash,
        required_partitions=req, executed_partitions=exe,
        omitted_partitions=omitted,
        anchors_required=a_req, anchors_exercised=a_exe,
        anchors_missing=a_missing,
        corpus_can_trigger_target=corpus_can_trigger_target,
        coverage_complete=complete, negative_claim_admissible=admissible,
        reason=reason)


# --------------------------------------------------- completeness, not booleans

@dataclass(frozen=True)
class SpectrumCompleteness:
    """Which weights a sweep's multiplicity tally is COMPLETE for.

    Replaces `multiplicity_is_complete: bool`. The producer states the depth it
    reached and the rule it claims; the weight range is DERIVED, so a verifier
    recomputes it from the same two facts rather than trusting a flag.

    THE RULE, named so it can be argued with: under qubit-paired enumeration a
    weight-w operator has at most w nonzero qubits, hence at most w inside any
    pivot set, so depth p >= w enumerates every one of them from every set.
    Below that, the tally counts only operators whose support fell thinly across
    the pivots -- a property of the information set, not of the code.
    """
    completed_depth: int
    accumulator_cap: int
    observed_count: int
    completion_rule: str = "paired_zimmermann_p_ge_w"
    completion_rule_version: str = "1"

    @property
    def complete_through_weight(self) -> int:
        """Highest weight whose tally is exhaustive; 0 when the cap was hit."""
        if self.observed_count >= self.accumulator_cap:
            return 0
        return max(0, int(self.completed_depth))

    def complete_for_weight(self, w: int) -> bool:
        return w <= self.complete_through_weight

    def status_for_weight(self, w: int) -> str:
        return ("complete" if self.complete_for_weight(w)
                else "partial_information_set_projection")

    def to_json(self, w: int | None = None) -> dict:
        out = {"completed_depth": int(self.completed_depth),
               "complete_through_weight": self.complete_through_weight,
               "completion_rule": self.completion_rule,
               "completion_rule_version": self.completion_rule_version,
               "accumulator_cap": int(self.accumulator_cap),
               "observed_count": int(self.observed_count)}
        if w is not None:
            out["weight"] = int(w)
            out["multiplicity_status"] = self.status_for_weight(w)
        return out
