# gitlawb economics

How $GITLAWB flows through the protocol and how stakers earn.

---

## TL;DR

- Every protocol fee (5% of completed bounties, plus future services) flows into `GitlawbFeeDistributor` — the protocol's reward wallet.
- Once per week, anyone can call `distribute()` to split the accumulated balance.
- **75%** goes to **node operators** (PoS staking — skin in the game).
- **24%** goes to **user stakers** (tier-weighted passive yield).
- **1%** goes to **the caller** of `distribute()` (keeper reward).

---

## Fee sources

All routed to `GitlawbFeeDistributor`:

| Source | Rate | How it gets there |
|---|---|---|
| Bounty protocol fee | 5% of payout | `GitlawbBounty.treasury` is set to the distributor — arrives on `approveBounty()` |
| Manual deposits (bankr) | variable | `token.transfer(feeDistributor, amount)` — any $GITLAWB sent to the address counts |
| Future: push/PR fees | TBD | node fees collected by operators, routed to distributor |

The distributor is a plain ERC20 holder — anything sent to it is fair game for the weekly split.

---

## The weekly split

```
distribute() — permissionless, enforced ≥ 7 days since last call
├── 1%  → msg.sender           (keeper reward)
├── 75% → GitlawbNodeStaking   (operator PoS rewards)
└── 24% → GitlawbStaking       (user tier-weighted rewards)
```

Split is owner-adjustable but capped to ±5% change per update (prevents abrupt reallocations).

---

## Node operator staking (75% track)

**Contract:** `GitlawbNodeStaking.sol`

Node operators **must** stake to run a node and earn rewards.

| Parameter | Value |
|---|---|
| Minimum stake | 10,000 $GITLAWB |
| Heartbeat cadence | 24 hours |
| Inactive threshold | 3 days (no heartbeat → excluded from rewards) |
| Unstake cooldown | 7 days |

**Reward formula** (per node, per weekly distribution):

```
nodeReward_i = nodeShare × (myStake / totalActiveStake)   if heartbeat within 3 days
nodeReward_i = 0                                            otherwise
```

**Worked example — 5 active nodes**, all at 10k stake, weekly pot = 100k $GITLAWB:
- Node share (75%) = 75k
- Total active stake = 50k
- Each node earns: `75k × (10k / 50k)` = **15,000 $GITLAWB/week**

If one node goes offline, the active pool shrinks and remaining nodes earn more — the offline node gets nothing, its share redistributes.

**Skin in the game:** no automatic token slashing in v1, but offline nodes earn zero. Repeated offenses + inflated stake = dead capital.

---

## User staking (24% track)

**Contract:** `GitlawbStaking.sol`

Anyone can stake $GITLAWB for passive yield. Four tiers with multipliers:

| Tier | Min stake | Multiplier |
|---|---|---|
| Observer | 1,000 | 1x |
| Curator | 10,000 | 2x |
| Steward | 100,000 | 4x |
| Validator | 1,000,000 | 8x |

**Reward formula** (per staker, per weekly distribution):

```
userReward_i = userShare × (myStake × myMultiplier / totalWeightedStake)
```

**Worked example — mixed tiers**, weekly pot = 100k → user share = 24k:

| Staker | Stake | Multiplier | Weight |
|---|---|---|---|
| 5× Observer | 1k each | 1x | 5,000 |
| 3× Curator | 10k each | 2x | 60,000 |
| 2× Steward | 100k each | 4x | 800,000 |
| **Total weighted** | | | **865,000** |

- Each Observer: `24k × (1k / 865k)` ≈ **27.7 $GITLAWB/week**
- Each Curator:  `24k × (20k / 865k)` ≈ **555 $GITLAWB/week**
- Each Steward:  `24k × (400k / 865k)` ≈ **11,098 $GITLAWB/week**

**Unstake cooldown:** 7 days.

---

## Keeper reward (1% track)

The caller of `distribute()` receives 1% of the pot. At 100k weekly, that's 1,000 $GITLAWB.

Why: removes operational burden. Even if the official keeper misses a run, any staker or searcher has financial incentive to call it.

Operators can run a weekly keeper job that calls `distribute()`; the caller wallet self-funds its gas from the 1% reward.

---

## End-to-end flow

```
                    ┌─────────────────────────────────────────┐
                    │  Fee sources                            │
                    │  ┌─────────────┐  ┌─────────────┐       │
                    │  │Bounty 5%    │  │Bankr manual │  ···  │
                    │  └──────┬──────┘  └──────┬──────┘       │
                    └─────────┼─────────────────┼─────────────┘
                              ↓                 ↓
                    ┌─────────────────────────────────────────┐
                    │  GitlawbFeeDistributor                  │
                    │  (the protocol reward wallet)           │
                    └──────────────────┬──────────────────────┘
                                       │
                        distribute()   │  weekly, permissionless
                                       ↓
                ┌──────────────────────┼──────────────────────┐
                │                      │                      │
           ┌────▼────┐        ┌────────▼────────┐      ┌──────▼──────┐
           │ 1%      │        │ 75%             │      │ 24%         │
           │ caller  │        │ NodeStaking     │      │ UserStaking │
           └─────────┘        │ (pro-rata:      │      │ (pro-rata:  │
                              │  stake × active)│      │  stake × m) │
                              └─────────────────┘      └─────────────┘
```

---

## Tuning

- `FeeDistributor.setSplit(nodeBps, userBps, keeperBps)` — owner only, sum must = 10000, each field can change ≤ 500 bps per update.
- `FeeDistributor.setSinks(...)` — swap staking contracts if upgrading.
- `GitlawbBounty.setProtocolFee(bps)` — fee cap 1000 bps (10%).

Any change is observable on-chain before it takes effect — integrators watch events.
