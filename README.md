# RUNNERS independent replay

**144,542 wallets · 18 categories · 156,259 stacked awards · 1 billion RUNNERS · zero reserve.**

This package is designed to rebuild the eligibility lists, cluster exclusions and every gross award from a pinned historical evidence artifact. `criteria.md` states the exact rules and source limits. `PROJECTION.md` explains what was removed for privacy and what source authenticity is not established by replay.

No wallet connection, signing, transaction, credentials or live RPC is needed. Review the code before running it. Use an empty working directory, no secrets or wallet files, and deny network access during replay.

## Full verification

Use Python **3.10+** and Node **18+**. Python uses only the standard library. Node's raw strategy decoder uses the included offline codec; no `npm install` is needed. The code and evidence must both be pinned independently. Obtain `evidence-index.json` and its advertised SHA-256 from the reviewed release, then extract the listed data parts into `evidence/`. `fetch_data.py` supports either local parts or an explicitly supplied public asset base URL.

Allow several gigabytes for the evidence and generated reports, and time for a full CPU replay. The local checks used Python 3.10 in an isolated offline environment. Cross-platform execution has not been independently tested.

```sh
python3 -I -B fetch_data.py --index evidence-index.json --index-sha256 9fd895460c9dbe59c3e10b98cb805b1debc629b6bcd8814f4116920bf198689b --from-directory artifacts --destination evidence
python3 -I -B reproduce.py --data evidence --manifest-sha256 9b536b62069f3dd38b752dcd3562fad05fe67ea30252d496965e0aab48e642cc --all --out replay-output
python3 -I -B verify.py
```

The local candidate includes the exact index, data-manifest pin and measured results in the separate local release report `REVIEW.json`. That report identifies the validated implementation commit; it is generated after that commit to avoid a circular hash. No public asset location is invented before publication.

`reproduce.py --all` validates the full file inventory, rebuilds all category prelists from source facts, rebuilds the service/cluster exclusions, compares every exclusion reason and final category list, then calculates the allocations using the regenerated lists. Supplied expected lists are comparison targets. They are never the full replay's selector inputs. A missing stage, capture, required proof, mismatching list or CSV prevents a full success result.

The allocation must be exactly **1,000,000,000,000,000 base units**, at six decimals, with no unallocated amount. Distinct categories stack. Fixed shares and fixed awards are checked first; remainder weights use rational arithmetic and largest-remainder rounding with category-ID tie breaks. Residual base units within each category go to wallets in sorted order.

Expected `claims.csv` SHA-256:

```text
4d78c121a841c28c3a02963a0bf5266166aa963e42eafe60d615f715ebd731a2
```

For a quick allocation-only cross-check, the reviewed original verifier remains available:

```sh
python3 -I -B verify.py --wallet PARTICIPANT_ADDRESS
```

That command starts from the final lists and does not establish source eligibility. A full replay can also produce a per-wallet explanation using `--wallet PARTICIPANT_ADDRESS`.

## Additional checks

After reviewing the scripts, run the boundary/decoder/privacy fixtures and the source-consistency mutation tests. The mutation harness uses temporary hardlinked copies, replaces files before modifying them, and leaves the evidence unchanged.

```sh
python3 -I -B -m unittest discover -s tests
python3 -I -B tests/adversarial_replay.py --data evidence --manifest-sha256 9b536b62069f3dd38b752dcd3562fad05fe67ea30252d496965e0aab48e642cc --out adversarial-replay
python3 -I -B privacy_scan.py artifacts --asset-index evidence-index.json --asset-index-sha256 9fd895460c9dbe59c3e10b98cb805b1debc629b6bcd8814f4116920bf198689b
```

The archive scan decompresses every member and retained encoded field and checks exact indexed coverage; it can take longer than replay. Private-marker checks used for this local review are supplied separately and are never part of the public payload. The six exact reviewed public-resource URL exceptions for code/metadata scans are listed in `REVIEW.json`; RPC endpoints have no exception.

## Files and outcomes

- `claims.csv`, `wallets/`, `allocation.json`: unchanged locked gross allocation inputs and comparison targets.
- `reproduce.py`, `replay/`: offline source derivation, exclusions and independent exact allocation implementation.
- `verify.py`: separately reviewed allocation cross-check.
- `evidence-index.json`, `artifacts/`: portable hash-pinned data parts; the extracted artifact has its own complete manifest and neutral relative paths.
- `tests/`: decoder, exact-arithmetic, privacy and tampering checks.
- `checksums.json`: current public code/docs/allocation file sizes and hashes. Historical checksums are not reused for modified documents.
- `REVIEW.json`: measured local verification results and precise outstanding limits.

A matching replay proves reproducibility from these historical inputs. It does **not** prove unsigned providers returned authentic and complete chain state, identify wallet owners, or turn the IslandDAO organizer roster into a publicly observable participation test. Eligible contributors receive the same criteria-based awards as other participants; there is no private owner exception.

The optional `verify.py --distributor PUBLIC_ACCOUNT` computes the package's Merkle root for a supplied account address. It does not query the chain, establish the public distribution account, verify its program owner, or read its locked root. Those on-chain checks remain **NOT TESTED** unless separately established from independent public evidence.

Awards are gross. This replay does not simulate transfers or execute claims.
