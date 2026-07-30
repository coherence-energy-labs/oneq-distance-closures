# oneq-ibm-distance-closures-v1.0.1

Six entries in IBM's `qcode-discovery` catalogue carry `d_is_exact: false`
because the MILP left one or more logical operators as incumbents. This release
is the evidence that their distances are exact.

**IBM's published `d` is unchanged on all six.** This confirms their values; it
revises none of them.

| code | [[n,k]] | exact d | candidates/replica | evidence |
|---|---|---|---|---|
| `9_6_0172` | [[108,2]] | **10** | 49,256,436,180 | two replicas + independent reproduction |
| `0571f76786029653` | [[108,2]] | **10** | 49,256,436,180 | two replicas |
| `phase2_64` | [[108,6]] | **8** | 688,229,434,659 | two replicas |
| `phase2_65` | [[108,6]] | **8** | 688,229,434,659 | two replicas |
| `12_6_0199` | [[144,4]] | **12** | 8,149,473,282,198 | two replicas |
| `12_6_0201` | [[144,8]] | **8** | 4,945,164,656,133 | two replicas |

## The six are NOT equally independent

Read this before quoting a summary number.

- **All six** have two completed replicas built from **provably distinct**
  information sets, with candidate accounting that reproduces from a closed-form
  identity.
- **`9_6_0172` additionally** has its lower bound reproduced end to end by a
  **separately implemented runner that never invokes the production
  certification engine**. It rebuilt the information sets from recorded pivot
  qubits, recomputed the deficiencies, and checked all 49,256,436,180 candidates
  across 582 shards, finding zero violations and minimum logical weight 10.

Every closure carries `independence_level` as a field, so the distinction
travels with the artifact rather than living only here.

## Verify

Self-contained -- `PYTHONPATH=.` and nothing else:

```
PYTHONPATH=. python verifiers/verify_closures.py          # seconds
PYTHONPATH=. python verifiers/challenge_lower_bound.py    # minutes
```

See `reproduce/VERIFY.md` and `LIMITATIONS.md`.

## Method

Qubit-paired Brouwer-Zimmermann enumeration: the two symplectic columns of each
physical qubit stay adjacent through row reduction, so every pivot qubit owns
{X, Z, Y} directly. The bound applies to **qubit weight** with no factor-2
slack, and Zimmermann's rank-deficient refinement admits a second information
set whose deficiency is measured rather than assumed:

    d >= SUM_i max(0, p + 1 - deficiency_i)
