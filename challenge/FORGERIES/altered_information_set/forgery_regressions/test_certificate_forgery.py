"""The stranger verifier must REFUSE forged certificates. Four attacks.

WHY THIS FILE EXISTS. The red team defeated `verify_closures.py` by editing two
numbers in a promoted artifact -- `lower_bound` 8 -> 16 and one set's
`deficiency` to 0 -- and the verifier printed "claimed d = 16" while looking
straight at a weight-8 witness. The fix landed. The REGRESSION did not, which
means the repair was protected by nothing but memory. A security fix with no
test that fails without it is a comment.

Each attack below is a specific way to make a false claim look verified. Each
must be rejected, and the unmodified artifact must still be ACCEPTED -- without
that last control the whole file could pass by refusing everything, which is the
vacuity species this program keeps finding in its own gates.

  A1  raise the claimed distance and zero a deficiency to fund it
      -> caught by tying each set's contribution to its OWN recorded depth
  A2  swap in a different information set, leave the provenance block alone
      -> caught by RECOMPUTING the hashes instead of reading them back
  A3  copy replica 0's search into replica 1 and call it independent
      -> caught by comparing information-set hashes across replicas
  A4  present a schema-1 artifact, which no verifier below the floor could
      have checked for A1 at all
      -> caught by the promotion floor
"""

from __future__ import annotations

import copy
import json
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

from verify_closures import _catalogue, _records, verify_instance   # noqa: E402


def _accepted(v: dict) -> bool:
    """The verdict the promotion pipeline actually acts on."""
    wit = all(x.get("witness_proves_upper_bound") for x in v["replicas"])
    arith = all(x["bound_supported_by_depth"] and x["all_contributors_fully_swept"]
                for x in v["replicas"])
    return bool(v["code_rebuilds"] and v["replicas_agree"] and arith and wit
                and v["all_replicas_promotable"]
                and v["replica_information_sets_distinct"])


@pytest.fixture(scope="module")
def genuine():
    try:
        cat = _catalogue()
    except Exception:                                    # pragma: no cover
        pytest.skip("IBM catalogue not present in this checkout")
    recs = [r for r in _records() if r.get("status") in ("CLOSED", "IMPROVED")
            and len(r.get("certificates", [])) > 1]
    if not recs:                                         # pragma: no cover
        pytest.skip("no multi-replica closure artifacts present")
    recs.sort(key=lambda r: r["n"])
    return recs[0], cat


def test_genuine_certificate_is_accepted(genuine):
    """The control. Without it, a verifier that refuses everything passes."""
    rec, cat = genuine
    assert _accepted(verify_instance(copy.deepcopy(rec), cat)), \
        "the unmodified artifact must verify -- otherwise the rejections below prove nothing"


def test_A1_inflated_bound_funded_by_a_zeroed_deficiency_is_refused(genuine):
    """The red team's original exploit, replayed."""
    rec, cat = genuine
    forged = copy.deepcopy(rec)
    for cert in forged["certificates"]:
        cert["lower_bound"] = cert["lower_bound"] * 2      # 8 -> 16
        cert["sets"][-1]["deficiency"] = 0                 # fund the inflation
    v = verify_instance(forged, cat)
    assert not _accepted(v), "the certificate-forgery exploit is live again"
    assert not all(x["bound_supported_by_depth"] for x in v["replicas"]), \
        "the bound must fail against the depth actually enumerated"


def test_A2_substituted_information_set_is_refused(genuine):
    """Hashes must be RECOMPUTED. A hash that is only read back checks nothing."""
    rec, cat = genuine
    forged = copy.deepcopy(rec)
    sets = forged["certificates"][0]["sets"]
    if not sets[0].get("pivot_list"):                    # pragma: no cover
        pytest.skip("artifact predates pivot_list capture")
    sets[0]["pivot_list"] = list(reversed(sets[0]["pivot_list"]))[:-1] + [9999]
    v = verify_instance(forged, cat)
    assert not _accepted(v), "a swapped information set passed unnoticed"
    assert "information_set_hash" in v["replicas"][0]["hash_mismatches"], \
        "the recomputed information-set hash must disagree with the recorded block"


def test_A3_duplicated_replica_is_not_independent(genuine):
    """Two runs of the SAME set agree by construction and confirm nothing."""
    rec, cat = genuine
    forged = copy.deepcopy(rec)
    forged["certificates"][1]["sets"] = copy.deepcopy(
        forged["certificates"][0]["sets"])
    v = verify_instance(forged, cat)
    assert not v["replica_information_sets_distinct"], \
        "identical information sets were reported as independent replicas"
    assert not _accepted(v)


def test_A4_schema_1_artifact_is_verifiable_but_not_promotable(genuine):
    """Below the floor: still checkable, no longer promotable on old authority."""
    rec, cat = genuine
    old = copy.deepcopy(rec)
    for cert in old["certificates"]:
        cert.pop("provenance", None)
        cert.pop("schema_version", None)
    v = verify_instance(old, cat)
    assert not v["all_replicas_promotable"], \
        "an unversioned certificate must not be promotable"
    assert not _accepted(v)
    # ...but the parts that ARE self-contained must still verify, or we would be
    # discarding real evidence rather than scoping it.
    assert all(x["witness_proves_upper_bound"] for x in v["replicas"]), \
        "the witness is self-contained; the floor must not invalidate it"


def test_promotion_floor_rejects_every_superseded_schema():
    from oneq.provenance import (SUPERSEDED_SCHEMAS, VERIFIER_MIN_VERSION,
                                 version_at_least)
    for s in SUPERSEDED_SCHEMAS:
        assert not version_at_least(s, VERIFIER_MIN_VERSION), \
            f"schema {s} predates the forgery fix and must not be promotable"
    assert version_at_least(VERIFIER_MIN_VERSION, VERIFIER_MIN_VERSION)


def test_artifacts_declare_the_lower_bound_is_not_machine_checkable(genuine):
    """The claim boundary must travel INSIDE the artifact, not only in our prose.

    A certificate quoted without our documentation must still tell a reader that
    the lower bound needs re-execution.
    """
    rec, _cat = genuine
    for cert in rec["certificates"]:
        prov = cert.get("provenance") or {}
        assert prov.get("lower_bound_is_machine_checkable") is False
        assert "re-execution" in prov.get("lower_bound_verification", "")


# ------------------------------------------- the INPUT, not just the artifact

def test_the_catalogue_is_pinned_by_content(genuine):
    """A verifier must identify its input before drawing conclusions from it.

    THE FAILURE THIS PINS. This program applied its own proposed upstream edit
    to its working copy of IBM's catalogue and then kept verifying against it,
    reading `published_is_exact: true` for rows IBM publishes as unresolved --
    112 open rows where the real catalogue has 117. Nothing detected it, because
    nothing had recorded what the input was supposed to be.
    """
    from oneq.provenance import catalogue_is_pinned
    _rec, cat = genuine
    pinned, digest = catalogue_is_pinned(list(cat.values()))
    assert pinned, (f"catalogue digest {digest} is not the pinned revision -- "
                    "the working copy may have been edited")
    assert sum(1 for r in cat.values() if not r.get("d_is_exact")) == 117, (
        "IBM publishes 117 unresolved rows; this catalogue disagrees")


def test_editing_one_field_breaks_the_catalogue_pin():
    """The control: the digest must be sensitive, not decorative."""
    import copy
    from oneq.provenance import catalogue_digest
    rows = [{"code_id": "a", "d": 8, "d_is_exact": False, "n": 108},
            {"code_id": "b", "d": 10, "d_is_exact": True, "n": 144}]
    base = catalogue_digest(rows)
    assert catalogue_digest(list(reversed(copy.deepcopy(rows)))) == base, \
        "digest must survive row REORDERING -- it is content, not formatting"
    flipped = copy.deepcopy(rows)
    flipped[0]["d_is_exact"] = True
    assert catalogue_digest(flipped) != base, \
        "flipping d_is_exact went undetected -- exactly tonight's contamination"
    changed_d = copy.deepcopy(rows)
    changed_d[1]["d"] = 12
    assert catalogue_digest(changed_d) != base
