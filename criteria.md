# Final eligibility criteria

The reference slot is **458,146,998**, selected October 17, 2026 at 19:08 UTC. Each category is rebuilt from the captured source facts below; older immutable transaction captures and disclosed frozen registries are reused where required. Earlier approved cohort rosters are not merged into refreshed on-chain lists. The organizer roster and public legacy indexes are explicit source inputs where stated. Historical activity is bounded by the reference slot. Current balances and positions were read after it, using finalized responses at or above that slot; these are collection-window observations, not an exact historical account-state replay. Meteora current values were collected about 13 hours later.

| Category | Rule |
|---|---|
| Seeker | Holds a genuine Seeker Genesis Token, verified by its official metadata pointer and token-group membership, and at least 0.1 SOL of native plus qualifying wrapped SOL. One category award per wallet, regardless of credential count. |
| Meteora LPs | At least $100 combined current open DLMM and DAMM v2 liquidity. Non-SOL/USDC/USDT value is capped by the base liquidity in the pool used to price it. DAMM v2 positions are attributed to the current position-NFT holder. Account screen excludes incompatible program accounts. |
| Phoenix Perps | At least $10,000 cumulative executed perps volume in the captured public leaderboard, summed across linked subaccounts. Only directly claimable participant addresses are included; public-source coverage is a lower bound. |
| Symmetry | At least one successful positive deposit, mint, redemption or user-token claim in the supported current or legacy programs through the reference slot. Attribute the beneficiary rather than a keeper or fee payer. |
| Squads teams | Every on-curve member key of a qualifying team multisig, including members without Vote permission. The team requires at least 2 approvals, no external controller, 2–20 voters, threshold no greater than its voter count, no member appearing in more than 20 decoded multisigs, at least 25 proposals, and activity within the preceding 365 days. Off-curve member keys are excluded. |
| Kamino | At least $100 deposited and at least $100 borrowed, combined across obligations and qualifying Earn shares. Lending uses the obligation's cached on-chain deposited/borrowed USD values, including stale-flagged values; this does not refresh oracle valuations. Earn value uses the captured vault USD-per-share, mint precision and directly held shares. |
| P0 | At least $100 deposited and at least $100 borrowed across P0 accounts, using captured bank share values and oracle prices. |
| Jupiter Lend | At least $100 collateral and at least $100 debt across qualifying vault positions. Earn-only deposits do not qualify. |
| Sanctum INF | At least $100 of directly held INF, valued using captured pool SOL value, supply and SOL/USD. Indirect protocol custody is not attributed to the depositor. |
| Exponent | At least $100 combined current qualifying product principal at captured prices. Unpriced principal, custody addresses and unclaimed rewards are not added. |
| Hylo | At least $100 combined current qualifying official product value at captured marks/NAV. Custody is not double-counted. |
| xStocks | At least $100 combined qualifying xStocks holdings. Apply the captured issuer/service exclusion and compatible-account screens. |
| ZEC | At least $100 qualifying ZEC holdings, with the compatible-account and service screens. |
| HYPE | At least $100 qualifying HYPE holdings, with the compatible-account and service screens. |
| Builders | Current holders of genuine live Solfate DevList Membership NFTs, verified against the credential's authorities, extensions, metadata and supply. |
| IslandDAO | The fixed 168-participant roster. Source: **Provided by the IslandDAO organizers**. No additional balance, activity or social-account requirement. |
| Ride | Verifiable current and legacy funded users, including withdrawn or settled positions. No USD minimum or current-balance requirement. |
| Overpass | At least $100 combined directly held deposit receipts from the official registry, valued at captured NAV. Exclude incompatible program/custody accounts and protocol vaults. |

Distinct category awards stack. Duplicate entries within a category do not. No X account or handle is required. Legitimate eligibility does not depend on whether a participant is known to, or is, a project contributor. Wallet owners are not identified or labelled in this package.

**Squads wording correction:** the earlier package said “Voting member.” The historical selector actually included all on-curve member keys of qualifying teams. The voter count is a team qualification gate; member keys do not receive an additional account-owner screen. This corrects the description to the implemented rule; the frozen lists and claims are unchanged.

## Cluster exclusions

The final lists apply the deterministic first-funder cluster screen below. A cluster has at least 10 listed participants sharing the first observed positive native-SOL funding source. The source is taken from the first successful transaction history pages of 10, 40 and 100 rows (maximum 150), through slot 458146998, using instruction order, token-account closures and the documented balance-delta fallback. Unknown funders are reported and do not become clusters.

Labelled exchanges, issuers and services do not form exclusion clusters. The frozen service rules combine the pinned Dune Solana exchange rows, issuer-address captures and captured service category labels. Personal names and social fields are not used. A controller is the published mechanical test: an on-curve address or a System-owned account. It does not prove a person's identity. A source with 1,000 sampled activity rows within 24 hours is treated as a busy hot wallet and is exempt. A remaining cluster is excluded when any of these holds:

- At least 25 participants, with at least 80% funded within 7 days and at least 80% receiving amounts within 2% of the median.
- At least 80% funded within 24 hours and at least 80% receiving near-identical amounts.
- At least half returning funds to the funder or a cluster-specific common destination, plus either the 7-day burst or near-identical amounts.

A return sample combines the first-funder history and the 10 latest successful transactions through the reference slot. A common destination must receive flows from at least 3 cluster members, be unlabelled as a service, and receive at least half of its sampled listed-wallet senders from this cluster. The destination with most cluster senders is selected, with address order breaking ties. The amount reference is the **lower median**, sorted funding amounts at index `(n - 1) // 2`, including even-sized clusters. Similarity includes exactly ±2% of that integer amount; 80% and 50% thresholds include equality. Time windows are closed: exactly 24 hours or 7 days apart still count. These tests use integer arithmetic, without rounded percentages.

A listed funder operating an excluded cluster is also removed, unless already removed as a funded member. The final screen removes 3,386 unique participants and 3,412 category memberships: 3,368 funded members and 18 additional listed funders, from 50 excluded clusters. The package publishes the wallet/transaction facts and rule decisions needed to replay this screen, without identifying owners.

## Source and capture limits

These criteria apply to the exact captured source universes and versions in the pinned evidence artifact. Standard RPC does not reconstruct arbitrary historical account state. Re-running collection against current balances cannot reproduce an October 2026 observation.

- Seeker discovery combines the official metadata URI index, both frozen flags, and the Token-2022 metadata-pointer scan; raw mint self/group/supply and holder proofs are rechecked. Native/wrapped funds are collection-window observations. Original funds queries used finalized commitment without `minContextSlot`; returned context slots are checked against the reference. Group counters do not prove that an index exposed every historical holder.
- Meteora uses exhaustive captured DLMM PositionV2 and DAMM v2 Position scans and captured pool/bin/NFT-holder state. The legacy Position scan is empty. Amount math follows the captured official IDLs (DLMM SDK 1.9.14; cp-amm SDK 1.5.1). The USD method uses integers and 60-digit decimals, SOL from the median of the five deepest captured SOL/USDC pools, and USDC/USDT at USD 1. Non-quote sides use the selected pricing pool's quote-depth cap per position side. Fees, rewards, DAMM v1, limit orders and off-curve custody are excluded. Reads span October 18 roughly 08:24–10:30 UTC. Opened/changed positions and NFT transfers after the reference can affect attribution; unpriced and missing-account cases are explicitly reported.
- Phoenix is the captured public leaderboard universe across four sorts. Lifetime-volume lower bounds are used where they prove the threshold before the reference; boundary cases use captured fills through the reference. Public opt-outs and inaccessible users remain a coverage limit.
- Symmetry uses fresh V3 history, pinned immutable older legacy-authority history through slot 447525400, contiguous fresh legacy history thereafter, legacy-program cross-checks and empty tail rechecks. SDK/on-chain IDL role projections determine beneficiaries. Provider-relative terminal pagination cannot prove a provider returned every chain transaction.
- Squads scans three captured program versions and decodes their raw memberships and permissions. The latest transaction at or before the reference determines activity; it is not evidence of a particular member's participation.
- Holder, Kamino, P0, Jupiter Lend, INF, Exponent, Hylo and Overpass USD values use their disclosed captured oracle, cached NAV, indicative market or API values. They are observations across separate slots, not executable quotes. Unpriced products, unsupported layouts, indirect custody and unresolved NFT ownership remain recorded limits. Exponent SDK layouts are pinned at 0.9.29; the replacement offline decoder is checked against every historical strategy record. Jupiter integer tick/liquidation math is checked against every historical lend-read 0.0.14 borrower row.
- Solfate is a credential rule. Identity/social metadata pairs are unnecessary and omitted; required credential fingerprint strings, authorities, supply and holder facts remain.
- IslandDAO is exactly the organizer-provided roster and attribution. Replay verifies the fixed input and normalization; it does not assert an independently observable participation test.
- Exclusion evidence is a bounded first/latest-transaction sample and captured service classification. It is a reproducible screen, not proof that all common ownership has been discovered or that every excluded wallet has the same human owner.

Provider captures and organizer inputs are external assertions. Hashes and deterministic replay prove what follows from the published artifact. They do not authenticate unsigned RPC/API responses, original provider completeness, human ownership or organizer participation. See `PROJECTION.md` for the precise privacy transformation and trust boundary.
