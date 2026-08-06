# kekkai — the itonami

**結界 as an 営み**: the public, key-less half of a zero-trust mesh control
plane, mounted at
[`app.itonami.cloud/kekkai`](https://app.itonami.cloud/kekkai).

The engine lives elsewhere and is not duplicated here:
[`kotoba-lang/kekkai`](https://github.com/kotoba-lang/kekkai) is the control
plane (admission · netmap · routes · ACL, coord-LLM ⊣ TailnetGovernor) and
[`kotoba-lang/kekkai-node`](https://github.com/kotoba-lang/kekkai-node) is the
data plane (Noise IK sessions, NAT traversal, relay, MagicDNS). This repository
is a mount: it consumes `kekkai.acl` — the same pure `.cljc` the TailnetGovernor
censors proposals with — and adds an HTTP envelope and a payment gate.

> **Boundary with `kotoba-lang/kekkai`.** Same name, different face. That one is
> the engine; this one is the business it is sold as. Nothing decided here: if
> an answer this surface gives ever differs from the governor's, this surface is
> wrong.

## What it serves

| | | |
|---|---|---|
| `GET /health` | liveness | free |
| `GET /blueprint.edn` | the Open Business Blueprint | free |
| `POST /netmap/verify` | verify an Ed25519 signed-netmap envelope | **free** |
| `POST /x402/acl/decide` | one deny-by-default edge decision | USD 0.001 |

**It signs nothing.** Issuing a netmap means holding the authority key, and a
Worker reachable from the public internet is the wrong place to keep one.
Issuance stays on the control plane.

## What is metered, and what cannot be

The engine's charter (G4) is that there is **no `:traffic/*` and no
`:user/activity` namespace** — the control plane authorises reachability and
never records what flows through the tunnels. A per-gigabyte overlay would have
to measure gigabytes, so it cannot be built on this engine without contradicting
the property that makes the engine worth using.

So the meter is on **authorisation**, which the plane already decides and
already writes to its genealogy ledger. It is the only unit here that can be
counted without learning something the plane promised not to learn.

**Verification is free on purpose.** Charging to check whether an artifact is
authentic puts a price on the one action that protects the caller, and a node
that cannot afford to verify runs unverified — which is the exact failure the
signed-netmap boundary exists to prevent.

## The verifier is the third implementation of one check

There is a JVM one (`kekkai.envelope/verify`, publisher side), a Node one
(`kekkai.node.signed-netmap/verify-envelope`, node side), and this WebCrypto one
(`kekkai.itonami.verify`, edge). Three is normally a smell. What makes it
drift-proof rather than drift-prone is that all three are pinned to the same
bytes: `kotoba-lang/kekkai`'s `test/fixtures/netmap.signed.edn`, which that
repository asserts is byte-exactly what its publisher emits.

Measured 2026-08-06 against that fixture through `wrangler dev`: verified, and
the same envelope refused under a different authority
(`:untrusted-netmap-signer`).

## Payment

x402, thin mode — this seller keeps its own gate and delegates on-chain
verification to [`x402.nexus`](https://x402.nexus)
([`network-awai/nexus-x402`](https://github.com/network-awai/nexus-x402)). The
challenge is built by `pay.x402`, the same codec the facilitator runs on, so the
two agree by sharing a codec rather than by two readings of one spec.

The gate **fails closed, including when the facilitator is unreachable** — a
verifier that cannot reach `/verify` knows nothing about a payment, and
"unknown" is not "paid". The two closed doors are reported apart
(`:facilitator-unreachable` means wait, `:payment-invalid` means pay again),
because one undifferentiated 402 would send a caller who already paid to pay
twice.

## Build and ship

```bash
clojure -M:test     # the decision pass-through, on the JVM
clojure -M:lint
npm install
node ../../../scripts/resource-guard.mjs run build -- npx shadow-cljs release worker
npx wrangler dev --port 8799 --local     # smoke it before shipping
npm run ship                              # into ai-gftd-repository-dispatch
```

The script name, the repository name, and `blueprint.edn`'s
`:itonami.blueprint/mount` are all the string `kekkai`. They agree by being the
same string, not through a table — `itonami-fleet-dispatch` routes on the first
path segment and strips it, so this Worker sees `/health`, not
`/kekkai/health`.

## UI

`jp-go-dds` (デジタル庁デザインシステム), this workspace's base design system,
with app CSS written only against the `--hig-*` token contract that
`jp-go-dds.tokens/bridge-css` redefines on top of DADS primitives.

One measured caveat: the bridge carries 27 tokens and every one of them is
colour, palette, font-family or hairline. There is no `--hig-spacing-*`, no
`--hig-text-*-size`, no `--hig-radius-*`, and an unmapped custom property
resolves to *nothing* rather than erroring — `padding: var(--hig-spacing-4)`
silently collapses. Spacing here is `em`-relative for that reason.
