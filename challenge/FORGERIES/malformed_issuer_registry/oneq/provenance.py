"""Certificate identity: versions, hashes, and what each one actually proves.

WHY THIS EXISTS. The first five closures were promoted on artifacts carrying no
version of anything -- not the schema, not the engine, not the verifier. That was
survivable only while one person held the whole history in their head. It stops
being survivable the moment a certificate outlives the session that made it,
because the red team already demonstrated the failure mode: a verifier was
patched to close an exploit, and NOTHING in an older artifact records which side
of that patch checked it. A reader holding a certificate and a verifier has no
way to know whether that pairing was ever sound.

So every certificate now carries the identity of the thing that produced it and
the floor a verifier must meet to be allowed an opinion about it.

THE HASHES, AND PRECISELY WHAT EACH IS EVIDENCE OF -- they are not equivalent
and must not be presented as if they were:

  code_input_hash     the defining data (ell, m, monomials) as IBM published it.
                      Binds the claim to a code. Recomputable by anyone from the
                      catalogue; a mismatch means the claim is about a DIFFERENT
                      code than the row it is filed against.

  engine_fingerprint  sha256 over the engine sources as they sat on disk. Binds
                      the claim to a searcher. NOT a proof the search was
                      correct -- a fingerprint of a broken engine is a faithful
                      fingerprint of a broken engine. It exists so that when an
                      engine defect is found later, every certificate it touched
                      can be identified instead of guessed at.

  information_set_hash  the pivot qubits of each set. Binds the claim to the
                      decomposition actually used, and makes "two independent
                      replicas" a CHECKABLE statement rather than an assertion:
                      equal hashes across replicas means the second run repeated
                      the first, not that it confirmed it.

  witness_hash        the upper-bound operator. The one quantity here that is
                      self-verifying -- a reader recomputes the weight and the
                      commutation directly, needing nothing from us.

  candidate_plan_hash the (deficiency, contribution, levels_swept) triple per
                      set, at the depth reached. Binds the lower bound's
                      BOOKKEEPING. It does not bind the enumeration: identical
                      bookkeeping is exactly what a search that silently skipped
                      candidates would also report. Only re-execution binds that,
                      and saying otherwise is the failure this program exists to
                      avoid.

THE VERSION FLOOR is a refusal, not a warning. A certificate minted under a
schema older than the exploit fix is not "probably fine" -- it is unvalidated by
any verifier that can detect the exploit, and it is marked so.
"""

from __future__ import annotations

import pathlib
from typing import Any

from .passport import canonical_bytes, digest_obj, sha256_hex

# ---------------------------------------------------------------- versions
#
# SCHEMA 1.x  -- the five original closures. No provenance block. Verified by a
#                verifier that the red team exploited by editing `lower_bound`
#                8 -> 16 and one deficiency to 0.
# SCHEMA 2.0  -- provenance block required; verifier ties `contribution` to the
#                set's own recorded depth, requires EVERY set swept, and requires
#                lower == upper for `exact`. The exploit replays as blocked.
SCHEMA_VERSION = "2.0.0"

#: The searcher that produced a certificate. Bump on any change to enumeration,
#: pruning, or bound arithmetic -- not on comments or logging.
SEARCHER_VERSION = "2.0.0"

#: This build of `tools/verify_closures.py`.
VERIFIER_VERSION = "2.0.0"

#: The oldest verifier permitted to promote an exact-distance claim. Anything
#: below this could not detect the red team's certificate forgery, so its
#: verdicts carry no weight regardless of what they said at the time.
VERIFIER_MIN_VERSION = "2.0.0"

#: Schemas that predate the forgery fix. Readable, re-verifiable, and NOT
#: promotable until re-checked by a verifier at or above the floor.
SUPERSEDED_SCHEMAS = ("1.0.0", None)

#: The engine sources whose bytes define `engine_fingerprint`.
_ENGINE_SOURCES = ("bz.py", "gbb.py")


def _ver(v: str | None) -> tuple[int, ...]:
    if not v:
        return (0,)
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


def version_at_least(have: str | None, floor: str) -> bool:
    """Ordinary semantic-version comparison, tolerant of a missing version.

    A certificate with no version is treated as version 0 -- below every floor.
    That is deliberate: absence of a version is not evidence of compliance.
    """
    return _ver(have) >= _ver(floor)


def engine_fingerprint() -> dict[str, str]:
    """sha256 of each engine source, plus one digest over the set.

    Read from disk at call time so it describes the bytes that are actually
    imported, not a constant someone forgot to bump.
    """
    here = pathlib.Path(__file__).resolve().parent
    per = {}
    for name in _ENGINE_SOURCES:
        p = here / name
        per[name] = sha256_hex(p.read_bytes()) if p.exists() else "MISSING"
    return {"sources": per, "digest": digest_obj(per)}


def code_input_hash(row: dict) -> str:
    """Hash of a catalogue row's DEFINING data only.

    Deliberately excludes `d`, `d_is_exact`, and every other derived or
    annotative field -- those are the things a closure CHANGES. Hashing them
    would make the identity of the code depend on the answer, so a corrected row
    would no longer hash to the code it describes.
    """
    core = {k: row.get(k) for k in
            ("ell", "m", "A_terms", "B_terms", "C_terms", "D_terms", "n", "k")
            if row.get(k) is not None}
    return digest_obj(core)


def information_set_hash(sets: list[dict]) -> str:
    """Hash of the pivot-qubit decomposition actually enumerated.

    Falls back to the COUNTS when a schema-1 artifact never recorded the lists.
    That fallback is reported honestly by `is_hash_is_structural` below rather
    than silently producing a weaker hash that looks like the strong one.
    """
    if all("pivot_list" in s for s in sets):
        return digest_obj([{"index": s["index"], "pivot_list": list(s["pivot_list"])}
                           for s in sets])
    return digest_obj([{"index": s["index"], "pivot_qubits": s["pivot_qubits"],
                        "assigned_qubits": s["assigned_qubits"]} for s in sets])


def is_hash_is_structural(sets: list[dict]) -> bool:
    """True when the information-set hash covers the actual pivot qubits.

    False means it covers only their COUNTS -- which two genuinely different
    information sets can share, so replica-distinctness cannot be concluded
    from it. Callers must not report a counts-only hash as set identity.
    """
    return bool(sets) and all("pivot_list" in s for s in sets)


def candidate_plan_hash(cert: dict) -> str:
    """Hash of the lower bound's bookkeeping at the depth reached."""
    return digest_obj({
        "depth_p": cert.get("depth_p"),
        "sets": [{"index": s["index"], "deficiency": s["deficiency"],
                  "contribution": s["contribution"],
                  "levels_swept": s["levels_swept"]} for s in cert.get("sets", [])],
    })


def witness_hash(support: Any) -> str | None:
    return None if support is None else digest_obj(support)


def replica_id(code_hash: str, seed: Any, is_hash: str) -> str:
    """Short, deterministic name for one replica.

    Two replicas sharing a replica_id are the same computation, however
    separately they were launched.
    """
    return sha256_hex(canonical_bytes(
        {"code": code_hash, "seed": seed, "is": is_hash}))[:16]


def build_provenance(row: dict, cert: dict, *, seed: Any,
                     engine: dict | None = None) -> dict:
    """The block stamped into every schema-2 certificate."""
    eng = engine if engine is not None else engine_fingerprint()
    sets = cert.get("sets", [])
    ish = information_set_hash(sets)
    ch = code_input_hash(row)
    return {
        "schema_version": SCHEMA_VERSION,
        "searcher_version": SEARCHER_VERSION,
        "verifier_min_version": VERIFIER_MIN_VERSION,
        "engine_fingerprint": eng,
        "code_input_hash": ch,
        "information_set_hash": ish,
        "information_set_hash_covers_pivots": is_hash_is_structural(sets),
        "candidate_plan_hash": candidate_plan_hash(cert),
        "witness_hash": witness_hash(cert.get("witness_support")),
        "seed": seed,
        "replica_id": replica_id(ch, seed, ish),
        "completed_depth": cert.get("depth_p"),
        "backend": cert.get("backend"),
        # The claim boundary, carried IN the artifact so it travels with it and
        # cannot be lost when the certificate is quoted without our prose.
        "lower_bound_is_machine_checkable": False,
        "lower_bound_verification": "requires re-execution of the enumeration",
        "upper_bound_verification": "self-contained: witness weight + commutation",
    }


# ------------------------------------------------- the INPUT, pinned by content

#: sha256 over IBM's catalogue, canonicalised by row rather than by bytes so it
#: survives line reordering and whitespace but detects ANY field change.
#: Established from a pristine `qiskit-community/qcode-discovery` checkout.
PINNED_CATALOGUE_DIGEST = (
    "cb33f1c825d504e99daaac5178758d5e3ddb476240178c6909b2ce5896512bde")


def catalogue_digest(rows) -> str:
    """Content hash of a catalogue, insensitive to formatting, sensitive to data.

    WHY THIS EXISTS -- A FAILURE, NOT A PRECAUTION. This program applied its own
    proposed upstream edit to its working copy of IBM's catalogue and then kept
    verifying against it. Every run afterwards read `published_is_exact: true`
    for rows IBM publishes as unresolved: 112 open rows where the real catalogue
    has 117. Nothing detected it, because nothing had ever recorded what the
    input was supposed to be.

    Verification against data you can also write is not verification. The class
    is general -- a producer and a verifier sharing a mutable input -- and the
    fix is to make the input content-addressed and check it.
    """
    canon = sorted(
        digest_obj({k: r[k] for k in sorted(r)}) for r in rows)
    return sha256_hex("\n".join(canon).encode())


def catalogue_is_pinned(rows) -> tuple[bool, str]:
    """(is_the_pinned_revision, digest). Unpinned builds report False."""
    d = catalogue_digest(rows)
    if PINNED_CATALOGUE_DIGEST == "PENDING":
        return False, d
    return d == PINNED_CATALOGUE_DIGEST, d
