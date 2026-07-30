# Verify this release

Three checks, increasing cost. None requires trusting us.

## 1. Artifacts (seconds)

```
PYTHONPATH=. python verifiers/verify_closures.py
```

Rebuilds each code from IBM's row, verifies the witness is a genuine logical of
the claimed weight, **recomputes** every provenance hash rather than reading it
back, checks the replicas used distinct information sets, and refuses to promote
against a catalogue whose content digest does not match the pin.

## 2. Independent challenge of the lower bound (minutes)

```
PYTHONPATH=. python verifiers/challenge_lower_bound.py --budget 100000000
```

Rebuilds the enumeration from the recorded pivot qubits -- no seed replay, no
planner -- **recomputes the deficiencies**, enumerates the low-depth levels
exhaustively and samples above. Reports the bound the run EARNED:
`SUM_i max(0, L_i + 1 - d_i)` over the sets it actually exhausted.

## 3. Full re-execution (hours, shardable)

```
python experiments/gate0b_ibm825/close_open_instances.py --n 108 --k 2 --replicas 2 --max-p 7
```

The only route establishing exactness independently. The candidate space
partitions into contiguous index ranges, so this splits across machines. See
`independent_reproduction/9_6_0172/` for a completed example: 582 shards,
49,256,436,180 candidates, zero violations.
