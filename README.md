# RUNNERS final allocation

**144,542 participants · 18 categories · 1,000,000,000 RUNNERS · zero reserves.**

This package contains only the final participant lists, eligibility criteria, allocation rules and an independent offline allocation verifier.

- `claims.csv`: one row per participant, with its total gross award in base units. Divide by 1,000,000 for RUNNERS.
- `wallets/`: the 18 final category lists. Awards from different categories stack.
- `allocation.json`: category budget rules, exact totals, counts and checksums.
- `criteria.md`: the final eligibility criteria.
- `verify.py`: independently recomputes the budgets, rounding and every participant's award.
- `checksums.json`: file sizes and SHA-256 hashes.

## Verification

Python 3.10 or later, standard library only. No credentials or network connection are needed.

```sh
python3 -I -B verify.py
python3 -I -B verify.py --wallet PARTICIPANT_ADDRESS
```

The script must reproduce the final CSV byte for byte, with 144,542 participants, 156,259 stacked category awards and exactly 1,000,000,000 RUNNERS at 6 decimals.

The remaining budget after fixed-share and fixed-per-participant awards is split using the published remainder weights. Budgets use largest-remainder rounding, with category-id order breaking ties. Within each category, the budget is divided equally; leftover base units go to the first addresses in sorted order. Different category awards add together.

Final CSV SHA-256:

```text
4d78c121a841c28c3a02963a0bf5266166aa963e42eafe60d615f715ebd731a2
```

The verifier can also rebuild the Merkle commitment. Supply the public program-owned distribution account obtained independently from the claim service:

```sh
python3 -I -B verify.py --distributor PUBLIC_DISTRIBUTION_ACCOUNT
```

Expected root:

```text
256aa62ae42df907f0630982248f01af34b166af952a96b7c4d0af2c3a7fcbbb
```

The public distribution account is a program account, distinct from a participant or an operational wallet. No operational-wallet addresses are included in this package.

## Scope

This verifies the final distribution from the final category lists. It does not authenticate the underlying data providers or rerun eligibility collection. Provider-response bodies and intermediate research are not included. The criteria explain the sources and selection method; the committed CSV and optional Merkle check bind the resulting amounts.

Awards are gross entitlements. The token's 1% transfer fee can reduce net spendable receipts. Claims close January 20, 2027 at 00:00 UTC.
