"""Generalized / perturbed bivariate-bicycle (PBB) codes, reconstructed from
monomial exponent lists — with a self-check that refuses to return a code it
cannot prove it built correctly.

CONSTRUCTION (IBM's convention, `evaluation/pbb_code.py` in qiskit-community/
qcode-discovery). Over the abelian group Z_ell x Z_m with n = 2*ell*m qubits:

    x = P_ell (x) I_m        y = I_ell (x) P_m        (P = cyclic shift)
    A = sum_{(i,j) in A_terms} x^i y^j                (all sums mod 2)

The stabilizer matrix in symplectic form, columns [ X-part | Z-part ]:

    H = ( A   B  |  C   D  )
        ( 0   0  |  B^T A^T)

C = D = 0 recovers the CSS bivariate-bicycle code.

WHY THE SELF-CHECK MATTERS
A reconstruction that is subtly wrong produces numbers that look plausible and
are worthless. Before this module hands back a code it verifies, independently:

  1. **Commutativity.** Every pair of stabilizer rows must commute under the
     symplectic form: H_x Hz^T + H_z Hx^T = 0 (mod 2). A stabilizer group whose
     generators do not commute is not a code at all.
  2. **k matches the published value.** k = n - rank_2(H). If our k disagrees
     with IBM's, our matrices are not their matrices and every downstream
     distance claim is void.

Both are cheap and both are fatal if violated, so both are enforced.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def _shift(size: int, power: int = 1) -> np.ndarray:
    """Cyclic shift permutation matrix S with S[i, (i+power) % size] = 1."""
    m = np.zeros((size, size), dtype=np.uint8)
    idx = np.arange(size)
    m[idx, (idx + power) % size] = 1
    return m


def monomial(ell: int, m: int, i: int, j: int) -> np.ndarray:
    """x^i y^j  =  P_ell^i (x) P_m^j   as an (ell*m, ell*m) binary matrix."""
    return np.kron(_shift(ell, i % ell), _shift(m, j % m)).astype(np.uint8)


def poly_matrix(ell: int, m: int, terms) -> np.ndarray:
    """Sum of monomials over GF(2). An empty term list is the zero matrix."""
    dim = ell * m
    out = np.zeros((dim, dim), dtype=np.uint8)
    for i, j in terms or []:
        out ^= monomial(ell, m, int(i), int(j))
    return out


def gf2_rank(mat: np.ndarray) -> int:
    """Rank over GF(2) by Gaussian elimination. O(rows * cols * rows/64) with
    numpy row XOR; fast enough for the sizes here (216 columns)."""
    a = (np.asarray(mat) % 2).astype(np.uint8).copy()
    rows, cols = a.shape
    rank = 0
    for col in range(cols):
        pivot = None
        for r in range(rank, rows):
            if a[r, col]:
                pivot = r
                break
        if pivot is None:
            continue
        if pivot != rank:
            a[[rank, pivot]] = a[[pivot, rank]]
        mask = a[:, col].astype(bool).copy()
        mask[rank] = False
        a[mask] ^= a[rank]
        rank += 1
        if rank == rows:
            break
    return rank


def gf2_rref(mat: np.ndarray) -> tuple[np.ndarray, list[int]]:
    """Reduced row echelon form over GF(2); returns (rref, pivot columns)."""
    a = (np.asarray(mat) % 2).astype(np.uint8).copy()
    rows, cols = a.shape
    pivots: list[int] = []
    r = 0
    for c in range(cols):
        p = None
        for rr in range(r, rows):
            if a[rr, c]:
                p = rr
                break
        if p is None:
            continue
        if p != r:
            a[[r, p]] = a[[p, r]]
        mask = a[:, c].astype(bool).copy()
        mask[r] = False
        a[mask] ^= a[r]
        pivots.append(c)
        r += 1
        if r == rows:
            break
    return a[:r], pivots


def gf2_nullspace(mat: np.ndarray) -> np.ndarray:
    """Basis for {v : mat @ v = 0 (mod 2)}, returned as rows."""
    a = (np.asarray(mat) % 2).astype(np.uint8)
    rows, cols = a.shape
    rref, pivots = gf2_rref(a)
    free = [c for c in range(cols) if c not in set(pivots)]
    basis = np.zeros((len(free), cols), dtype=np.uint8)
    for bi, fc in enumerate(free):
        basis[bi, fc] = 1
        for ri, pc in enumerate(pivots):
            if rref[ri, fc]:
                basis[bi, pc] = 1
    return basis


@dataclass
class PBBCode:
    """A perturbed bivariate-bicycle stabilizer code."""
    ell: int
    m: int
    n: int
    k: int
    Hx: np.ndarray          # (rows, n)  X-part of the stabilizer matrix
    Hz: np.ndarray          # (rows, n)  Z-part
    code_id: str = ""

    @property
    def symplectic(self) -> np.ndarray:
        return np.hstack([self.Hx, self.Hz])

    def commutes(self) -> bool:
        """Symplectic inner product of every generator pair must vanish."""
        s = (self.Hx @ self.Hz.T + self.Hz @ self.Hx.T) % 2
        return not s.any()


def build_pbb(ell: int, m: int, A, B, C=None, D=None, *,
              code_id: str = "", expect_k: int | None = None) -> PBBCode:
    """Build a PBB code and REFUSE to return it unless it verifies.

    Raises ValueError if the stabilizers do not commute, or if `expect_k` is
    supplied and the computed k disagrees -- either means the reconstruction is
    not the code it claims to be.
    """
    mA, mB = poly_matrix(ell, m, A), poly_matrix(ell, m, B)
    mC, mD = poly_matrix(ell, m, C), poly_matrix(ell, m, D)
    dim = ell * m
    n = 2 * dim
    zero = np.zeros((dim, dim), dtype=np.uint8)

    Hx = np.vstack([np.hstack([mA, mB]), np.hstack([zero, zero])]).astype(np.uint8)
    Hz = np.vstack([np.hstack([mC, mD]), np.hstack([mB.T, mA.T])]).astype(np.uint8)

    code = PBBCode(ell=ell, m=m, n=n, k=0, Hx=Hx, Hz=Hz, code_id=code_id)

    if not code.commutes():
        raise ValueError(
            f"{code_id or 'code'}: stabilizer generators do not commute "
            "(A C^T + B D^T must be symmetric) -- reconstruction is wrong"
        )

    rank = gf2_rank(code.symplectic)
    code.k = n - rank
    if expect_k is not None and code.k != expect_k:
        raise ValueError(
            f"{code_id or 'code'}: reconstructed k={code.k} but the catalogue "
            f"publishes k={expect_k} -- the matrices are not the published code"
        )
    return code


def logical_basis(code: PBBCode) -> np.ndarray:
    """A basis for the logical operators, as symplectic vectors of length 2n.

    Logicals = centralizer(S) \\ S. The centralizer of the stabilizer group under
    the symplectic form is the nullspace of [Hz | Hx] (the symplectic partner of
    [Hx | Hz]); quotienting by the stabilizer rows leaves 2k independent logicals.
    """
    n = code.n
    sympl_partner = np.hstack([code.Hz, code.Hx])          # (rows, 2n)
    centralizer = gf2_nullspace(sympl_partner)             # rows span the centralizer
    stab = code.symplectic
    stab_rref, _ = gf2_rref(stab)
    stack = np.vstack([stab_rref, centralizer]) % 2
    rref, pivots = gf2_rref(stack)
    # rows of the quotient: centralizer rows independent of the stabilizer span
    out = []
    cur = stab_rref.copy()
    base_rank = gf2_rank(cur)
    for row in centralizer:
        trial = np.vstack([cur, row]) % 2
        r = gf2_rank(trial)
        if r > base_rank:
            out.append(row)
            cur, base_rank = trial, r
    return np.array(out, dtype=np.uint8) if out else np.zeros((0, 2 * n), dtype=np.uint8)


def symplectic_weight(v: np.ndarray, n: int) -> int:
    """Qubit weight of a symplectic vector: a qubit counts once if it carries
    X, Z, or Y (both)."""
    x, z = v[:n], v[n:]
    return int(np.count_nonzero(x | z))
