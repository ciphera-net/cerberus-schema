# cerberus-schema

The wire schema of the Cerberus bot-detection engine: the shape of an **observation**, the shape of
a **verdict**, and the closed **grammar** a detector uses to ask for evidence — plus a reference
implementation of that grammar and the conformance vectors that make "our adapter is equivalent" a
claim somebody can check.

**Zero dependencies**, standard library only, enforced by a test and by a second check over the
resolved build graph.

```bash
go get github.com/ciphera-net/cerberus-schema
```

## What is here, and what is deliberately not

This module is **shapes only**. There is no threshold, no token list, no allowlist, no honeypot
prefix, and above all no row of anybody's traffic.

That split is not squeamishness, it is a rule with a test attached: **publish a detector's shape iff
its evasion cost is recurring.** A statistical bar costs an adversary one parameter change to
evade — one-time and zero-marginal — so publishing it hands over the value and buys nothing. Making
a bot look like a person who sleeps, or exits from a real residential network, or actually scrolls,
costs money or throughput *every time*. The first belongs in a private pack. The second is safe to
describe, and describing it is the only way anyone can check the claims.

The corpus is a separate matter and is not a judgement call: Ciphera is a **processor** for that
traffic on its customers' behalf and cannot publish a controller's data at all, under any framing.

`TestPublishesShapesNeverNumbers` scans this repository for the shapes those artefacts take, so the
boundary is checked on every commit rather than remembered.

## The contract is additive-only

**A field may be added; none may be removed, renamed, or change type.** An enum may gain a value;
none may lose one or change meaning. This is the same promise the
[Pulse Public Read API](https://github.com/ciphera-net/pulse-api-go) makes, in the same words,
for the same reason: somebody else's build should never break because we tidied ours.

`TestContractIsAdditiveOnly` pins the current surface as a golden list, so a removal fails a test in
*this* repository rather than a build in yours. A deliberate break has to edit that list, which is
the point at which somebody has to justify it.

## The three things worth reading

### 1. The dedup unit is load-bearing, not incidental

`Spec.Unit` decides whether a scan counts events, sessions, or one row per session. Getting it wrong
is not an off-by-one — it is **a different rule**, and it shipped as a bug in the engine this schema
was extracted from.

The two conformance vectors that cover it share an identical substrate: six events across two
sessions, five from one visitor in DE and one from another in FR.

| unit | rows | country concentration (HHI) | what it reads as |
|---|---|---|---|
| `event` | 6 | (5/6)² + (1/6)² = **0.7222** | a homogeneous cohort |
| `session_first_event` | 2 | 0.25 + 0.25 = **0.5** | two people, one of whom clicked more |

An adapter that ignores the unit produces **the same answer for both vectors**. A conformance suite
carrying only one of the two files cannot see that, which is why
`conformance/03-dedup-unit-event-counts-every-row.json` and
`conformance/04-dedup-unit-session-first-event.json` exist as a pair, and why
`TestDedupUnitVectorsActuallyDisagree` fails if they ever stop disagreeing.

### 2. Timezone resolution is fail-closed, and that is a published requirement

In PostgreSQL 16, `AT TIME ZONE` on a browser-supplied zone the server does not know **aborts the
query** — it does not skip the row. An adapter that renders `timezone_resolvable` naively therefore
turns one piece of client junk into zero results for an entire scan. Dropping the row is the only
behaviour that degrades safely, and the vectors pin it in both directions: unresolvable zones drop
when the rule *declares* it needs a resolvable zone, and every row survives when it does not.

Legacy zone names resolve through an alias table. That is not tidiness either: one legacy spelling
covered 133 production sessions and was invisible to every timezone rule that listed only the modern
name.

### 3. The grammar cannot express a cross-site visitor record

There is no `group_by` key producing a `(fingerprint, site)` tuple, and `ScanResult` carries counts.
Cross-tenant reasoning may produce a **count** — "this configuration appeared on more than one
customer" — and may never produce a **membership list**, because a list of which sites a device
configuration visited *is* that record however it was assembled.

A lint over queries can be worked around by writing a different query. A grammar with no such key
cannot ask the question. `TestScanSpecCannotExpressCrossTenantMembership` asserts both halves: the
two keys exist separately, and no key combines them.

## Using it

Implement `Scanner` over your own storage and run the vectors against it:

```go
import cerberus "github.com/ciphera-net/cerberus-schema"

func TestMyAdapterIsConformant(t *testing.T) {
    vectors, err := cerberus.Vectors()
    if err != nil {
        t.Fatal(err)
    }
    for _, v := range vectors {
        adapter := NewMyAdapter(v.Observations, v.Now) // load the vector's substrate
        for _, err := range cerberus.CheckVector(adapter, v) {
            t.Error(err)
        }
    }
}
```

`MemoryScanner` is the reference implementation and defines the semantics. Where your adapter and it
disagree, it is right by construction — that is what "reference" means here.

Every expected value in the vectors was **computed by hand from the specification**, not captured
from the reference implementation. A vector generated by running the code it is meant to check
agrees with whatever that code does, including whatever it gets wrong.

## Scope

This is **stage 1** of a staged extraction: the schema, the grammar, the reference adapter, and the
vectors. The engine, the detector registry and the rule pack loader are **not** here and are gated
on separate conditions.

Vendoring this module back into the engine that produced it is a **later, separate decision** and
has not been taken. Saying so is better than half-doing it: a schema module that one consumer
imports and another shadows with a private copy is worse than either.

## Expect zero adoption

The value of this module is the boundary, not the audience. Ciphera's public repositories run at
single-digit stars and [Tessera](https://github.com/ciphera-net/tessera) has been public since June
2026 with no external contributions. If the case for extracting this rested on adoption, the case
would fail. It does not: the boundary is what stops a rule's semantics leaking into a private
adapter where no test can reach them, and that benefit accrues whether anyone else ever runs this or
not.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
