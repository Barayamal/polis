# Integrated Option C — signed synthetic identity to actual Pol.is

**13 September 2026 · Local synthetic engineering proof · Production/launch HOLD**

The formerly separate identity, activation and browser/access foundations are
now connected in a repeatable short-lived proof. This is Barayamal integration
code around self-hosted Pol.is, not an upstream ready-made eligibility product.

## What happens

1. The private test operator supplies a signed, bounded synthetic activation and
   separately opens only the new local test round.
2. The browser protocol starts a login with a rotated server cookie and CSRF.
   The private in-process driver explicitly injects an invented issuer response.
   A one-use same-origin JSON callback verifies the signed OIDC protocol using
   PKCE, state, nonce, issuer, audience, signature and expiry controls.
3. The same identity foundation issues a live private principal. The access layer
   maps its stable opaque account identity to a per-round HMAC-derived XID.
   Issuer-email assurance is required, but **no approval or invitation is granted**.
4. A signed, versioned WordPress-contract event must be acknowledged and applied.
   Forged signatures, absent approval, pending events and terminal revocation deny
   access. The strict path cannot use a fixture password or HTTP principal input.
5. A new invitation is bound to that account. An approved second account cannot
   redeem a forwarded copy; the matching account can still use the unconsumed
   invitation. Backend tokens and XIDs never enter browser responses.
6. The browser can receive only the exact known fixed seed statements and submit
   Agree, Disagree or Pass. The server rechecks identity, approval, signed
   activation, session and round state; actual Pol.is rechecks its scoped allowlist.
7. Signed revocation invalidates local authority, removes provider access and
   denies the next request from a warm session. Old/new approval events cannot
   revive a terminally revoked identity. Logout and expiry have separate tests.

## Repeatable checks

Use the existing isolated clone and installed locked identity dependencies. Local
tests need Node 26.8.2 (`node:sqlite`); the unsubmitted CI definition uses Node 24.

```sh
node --test deploy/fncp/identity-foundation/*.test.mjs deploy/fncp/local-access/integrated-access.test.mjs deploy/fncp/integrated-journey/*.test.mjs deploy/fncp/local-browser/*.test.mjs
```

These use generated signed tokens, actual loopback HTTP and a **model Pol.is**.
They require no Docker, real identity provider, WordPress installation or mail.

For the actual-origin proof, first start only the already-prepared isolated
Pol.is Compose stack and synthetic WordPress MySQL container using the owner
guide. Keep the original access/BFF/WordPress PHP applications stopped. Do not
rerun bootstrap, migrate or reapprove the preserved fixtures.

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/integrated-journey/real-origin-smoke.mjs
```

The runner pins the Docker context internally. It verifies container identity,
internal network, loopback ports, fixed configuration, fifteen distinct database
seeds/TIDs and the synthetic-only database scope before any vote. Its API, BFF and
event receiver use ephemeral loopback ports and **new private temporary stores**.
It creates exactly two new opaque provider identities and dispatches at most one
invented vote per invocation. In final cleanup it closes its authority, terminally
removes/readbacks only its own identities, checks original-store preservation and
stops all owned listeners. New temporary access/authority stores are removed only
after a verified pass; uncertain cleanup retains them. Original source stores and
synthetic votes/tombstones are not deleted.

Read [the verified increment report](../LOCAL-C-INTEGRATED-2026-09-13.md) and
[final aggregate actual-origin evidence](../evidence/integrated-origin-2026-09-13T04-19-21-395Z.json).
The default legacy startup at port 8100 is **not** this strict composition.

## Historical scope of this earlier proof

The boundaries below describe this report's earlier standalone invocation.
Subsequent [seamless WordPress and four-store recovery work](../LOCAL-C-SEAMLESS-RECOVERY-2026-09-13.md)
completed the local PHP registration/admin/outbox integration and actual closed
data restore. Do not treat those completed tasks as still outstanding, or combine
separate HTTP/UI-model results into a production end-to-end browser claim.

- No real issuer, real mailbox, heritage verification, participant account or
  invitation delivery. Synthetic issuer-email claims are not evidence of ancestry.
- HTTP cookie/CSRF protocol testing, **not rendered-browser or real HTTPS/OIDC
  redirect testing**. The `.invalid` callback is a private test input, never a
  navigated URL or an external request. Do not remove the guards to deploy it.
- Signed event receiver and fresh access journal, **not PHP WordPress UI/outbox
  integration with this new identity path**. The earlier actual WordPress/browser
  proof remains separate legacy evidence. Live page/form 12064/12069 are untouched.
- Single-process temporary authority/session stores and proof-only keys, not
  trusted production signing, durable production identity/key rotation, a
  distributed deployment or provider-wide closure/recovery.
- Existing image scans do not cover this new host-side composition. The previous
  three-store restore predates these new mappings/ledgers and later test votes.
- No external sends, submissions, commits, pushes, published changes or resources.

## Earlier next-work list (first two completed locally in later reports)

1. Integrate account binding into a new synthetic WordPress registration/admin
   flow, including authenticated operator ownership, outbox retry and negative
   tests. Do not reuse live registration records or ancestry evidence.
2. Extend recovery manifests to include strict identity mappings, activation
   ledger and identity-key versions; restoration must start closed and reject old
   cookies, invitations, activation and stale approvals.
3. Package the gateway/BFF and approved identity transport as reviewed release
   artifacts. Add exact image/lock provenance, secret custody, restart/partition
   tests and infrastructure-specific production controls.
4. Before any real issuer or deployment, use the owner decision pack for exact
   provider/region/cost/operator decisions and separate action-time approvals.

Primary guidance: [Pol.is source and Docker instructions](https://github.com/compdemocracy/polis/blob/stable/README.md),
[Pol.is configuration](https://github.com/compdemocracy/polis/blob/edge/docs/configuration.md),
[OpenID Connect claim stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability).
Upstream self-hosting instructions supply the engine/infrastructure starting
point; the custom approval/invitation controls require their own review.
