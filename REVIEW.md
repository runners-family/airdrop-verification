# Historical pre-publication review

This records the completed review before publication. See `README.md` and `PUBLICATION.json` for the numbered release attachments and current download index; archive contents, replay executables and locked allocation are unchanged.

The complete offline replay rebuilt all 18 category lists, the 3,386-wallet exclusion set and every gross award from the published historical captures. It reproduced **144,542 wallets, 156,259 stacked awards and exactly 1,000,000,000,000,000 base units**, with zero wallet, amount or CSV-byte differences. The original verifier also passed. See `REVIEW.json` and `REPLAY_RECEIPT.json` for measured results and pins.

## What to publish

Publish the reviewed code, documentation, locked allocation files, `evidence-index.json`, receipts and public inventory in the verification repository. Publish the **23 separately pinned data assets** as downloadable release assets; keep their bytes unchanged. The index pins every archive and member. The assets total **4,940,297,725 bytes**; each is below 512 MiB. No public download location is assumed before publication. The README contains the exact local fetch and full replay commands. `PUBLIC_FILES.json` inventories the intended payload; it excludes itself to avoid a circular hash.

Eligible contributor wallets follow the same criteria as everyone else and are not identified as contributors. IslandDAO remains exactly the fixed 168-wallet roster: **Provided by the IslandDAO organizers**. No additional attendance or attestation gate was added.

## Measured checks

All 14 source stages and all 18 regenerated final lists passed. The independent allocation implementations agree on every wallet and amount, and regenerated CSV bytes match the locked SHA-256 `4d78c121a841c28c3a02963a0bf5266166aa963e42eafe60d615f715ebd731a2`. The boundary/privacy/decoder suite passed 29 tests. Repinned-manifest insertion, omission and missing-page mutations were rejected by source replay. Exact strategy, borrower, liquidity-value, funder and cluster differential checks found no differences.

Every member of all 23 archives was decompressed and scanned, including embedded JSON and retained encoded fields. The conservative text scan returned **EXIT 1 with four marker observations**. Independent structural review accounted for all four as nonidentifying encoding coincidences in two canonical base64 account fields; the corresponding decoded bytes contain no marker. The raw result remains in `REVIEW.json`, with **zero unresolved findings**. Endpoint URLs, credential patterns, personal paths and unreadable inputs were zero. Two separate supplements checked base64/base58 fields and numeric byte vectors; each enforced exact archive/member coverage and found zero protected address matches. The vector supplement also applied the reviewed text/endpoint/credential/path patterns. Archive and inner gzip metadata are neutral. Code and release metadata were separately scanned and passed. Private transport records, identity/social fields, machine paths and private provenance crosswalks are absent from the intended public payload. These checks detect known patterns and markers; they do not prove that unknown personal associations are impossible.

## Corrections and remaining limits

Squads previously said “Voting member.” The actual selector includes every on-curve member key in qualifying teams; 2–20 voters is a team gate. **1,313 pre-exclusion and 1,065 final members** never have Vote permission in any qualifying active team. This documentation correction changes no wallet list or award.

The native-plus-wrapped Seeker check covers the two canonical wrapped-SOL ATAs, so **non-ATA wrapped-SOL coverage is NOT VERIFIED**. Native lamports count only for System-owned wallet accounts. These are disclosed implementation/capture limits, without silently narrowing the general criterion or declaring program/custody accounts newly eligible.

**Independent source authenticity and global completeness remain NOT VERIFIED.** Unsigned historical RPC/API captures are external assertions; hashes prove the published bytes and replay proves their consequences. Current balances cannot replace those captures. Provider-relative discovery, later collection windows, unpriced/unsupported products, unresolved NFT holders and custody limits remain explicit in `criteria.md`. IslandDAO replay verifies the organizer roster, not an independently observable participation test. The cluster screen does not prove human common ownership.

**Independent on-chain binding is NOT TESTED.** A verifier must first establish the public distribution account, program owner and locked root independently. The optional local Merkle calculator does not establish them. No signing or transactions are required for this package.

The measured implementation commit is recorded in `REVIEW.json`; release metadata is added afterward. No repository publication or push is performed by this local preparation.
