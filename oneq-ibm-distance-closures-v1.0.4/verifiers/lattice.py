r"""The soundness lattice, as a rule that can be violated.

WHAT THIS ENCODES. An external audit forged a distance claim and this
programme's verifier printed PROMOTABLE -- a word shaped like L4 PROVEN -- from
evidence that was only L1 REPLAY. The passport lattice already said
ACHIEVED = min(CLAIMED, REVERIFIABLE); nothing checked that the LANGUAGE a
result is published in respects it.

    is_violation(claimed=PROVEN, reverifiable=REPLAY) -> True

That single expression is the forgery, stated as arithmetic. A claim may always
be presented BELOW its evidence -- understatement is free. It may never be
presented above.

WHY THE PRESENTATION MATTERS AND NOT JUST THE FIELD. A reader does not compute
min(); they read a word. "PROMOTABLE", "verified", "certified exact" all read as
settled. If the strongest word in the artifact outranks the weakest link in its
evidence, the artifact lies regardless of what a nested field says -- which is
exactly how a certificate carrying `lower_bound_is_machine_checkable: false`
still managed to present as sealed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class L(IntEnum):
    """How a stranger checks a claim. Higher is stronger."""
    ASSERTED = 0     # a signature exists; trust reduces to the signer's word
    REPLAY = 1       # re-running reproduces it
    ATTESTED = 2     # ran inside measured hardware
    LOGGED = 3       # committed to a witnessed append-only log
    PROVEN = 4       # a succinct proof verifies it without re-execution


#: Words a publication may use, and the level each one READS as. A reader does
#: not parse a nested field; they read the strongest word on the page.
PRESENTATION = {
    "asserted": L.ASSERTED, "claimed": L.ASSERTED, "reported": L.ASSERTED,
    "reproducible": L.REPLAY, "replicated": L.REPLAY, "re-executed": L.REPLAY,
    "independently reproduced": L.REPLAY,
    "attested": L.ATTESTED, "hardware-attested": L.ATTESTED,
    "logged": L.LOGGED, "transparency-logged": L.LOGGED,
    "proven": L.PROVEN, "certified": L.PROVEN, "verified": L.PROVEN,
    "promotable": L.PROVEN, "exact": L.PROVEN, "guaranteed": L.PROVEN,
}


def achieved(claimed: int, reverifiable: int) -> int:
    """ACHIEVED = min(CLAIMED, REVERIFIABLE). Never more than either."""
    return min(int(claimed), int(reverifiable))


def is_violation(claimed: int, reverifiable: int) -> bool:
    """True when a claim is presented ABOVE what its evidence supports.

    is_violation(PROVEN, REPLAY) is True: the forgery, as arithmetic.
    is_violation(REPLAY, PROVEN) is False: understatement is always permitted.
    """
    return int(claimed) > int(reverifiable)


def level_of_phrase(text: str) -> int:
    """The strongest level any word in `text` reads as.

    Deliberately takes the MAXIMUM. A sentence that says "reproducible" and
    "certified" reads as certified to anyone skimming, and the weaker word does
    not repair the stronger one.
    """
    low = text.lower()
    best = L.ASSERTED
    for phrase, lvl in PRESENTATION.items():
        if phrase in low and lvl > best:
            best = lvl
    return int(best)


@dataclass(frozen=True)
class Audit:
    text: str
    presented_as: int
    reverifiable: int
    violation: bool
    reason: str

    def to_json(self) -> dict:
        return {"text": self.text, "presented_as": int(self.presented_as),
                "presented_as_name": L(self.presented_as).name,
                "reverifiable": int(self.reverifiable),
                "reverifiable_name": L(self.reverifiable).name,
                "violation": self.violation, "reason": self.reason}


def audit_phrase(text: str, reverifiable: int) -> Audit:
    """Does this wording outrun the evidence behind it?"""
    p = level_of_phrase(text)
    v = is_violation(p, reverifiable)
    return Audit(text, p, int(reverifiable), v,
                 (f"reads as {L(p).name} but the evidence supports only "
                  f"{L(int(reverifiable)).name}" if v else
                  f"reads as {L(p).name}, evidence supports "
                  f"{L(int(reverifiable)).name} -- within bounds"))
