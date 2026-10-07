# Signed activation foundation — synthetic only

This is a **local engineering proof, not an owner approval system, production deployment, or GO authority**. Nothing is sent, published or provisioned. The new wrapper does not replace the existing fixture-only startup or silently enable it. Do not remove its synthetic guards to deploy it.

The [integrated synthetic journey](../integrated-journey/README.md) now combines
this wrapper with signed synthetic OIDC, current WordPress approval and BFF
cookie/CSRF controls. It uses fresh stores and proof-only signing keys. Its
in-process identity method does not expose an HTTP activation or login bypass.

## Implemented

- Ed25519 signature verification over domain-separated canonical JSON. Strict schema, exact key ID, no algorithm negotiation, no runtime private signing key, and rejection of noncanonical/duplicate-key JSON or malformed base64.
- Exact binding to a configured synthetic deployment and conversation, five image digests, configuration/seed hashes, recovery epoch and a fresh verifier-generated boot nonce. The intended fixed scope is 20 fixtures, 15 statements and no suggestions.
- A separately signed, bounded lease (maximum 30 minutes in this proof), explicit operator activation, then a **separate** local round-open operation. Configuration alone cannot open the controlled API. There is no activation HTTP endpoint.
- Private SQLite authority ledger, monotonic activation sequence, one-use activation IDs and a live in-memory rollback floor. Every restart creates a new boot nonce and starts closed. Old signed authority, unused invitations, fixture authentication and participation sessions do not revive on restart or a new activation generation.
- Request-time admission before invitation issue/redemption and every participation read/write; checks repeated after awaiting the provider. Expiry, clock rollback, ledger failure or explicit close denies future participation. A transient storage recovery does not revive the old lease. Status, revocation and closure remain usable without positive activation.
- Controlled-mode fixture capacity is enforced at 20 retained synthetic identities, including restart refusal if an existing store exceeds the cap. Revocation does not free a slot for unlimited additional identities. Existing legacy fixture-only tests retain their previous behavior.
- Input snapshots, hook-override rejection, conversation cross-check when the provider exposes its conversation, separate-store path/inode checks, and independent cleanup attempts even when authority storage fails.

The signature binds the **supplied** configuration, image and seed values. The verifier does not independently discover or continuously attest the running infrastructure. The actual-origin runner measures the four running application image IDs, the build-only migration image, local configuration hash and source seed hash before/after its test. That is a bounded local observation—not independent database seed readback, trusted production measurement, immutable release evidence or approval of those images. The separate recovery proof performs database seed uniqueness/readback checks at its own checkpoint.

## Interfaces and test commands

`createActivationAuthority(options)` is in `authority.mjs`. `createControlledLocalAccess({activation,...access})` wraps the existing local fixture-only API and supplies the mandatory authority hook last, so a caller cannot substitute its own permissive guard. Private in-process methods are `activationBinding()`, `nextActivationSequence()`, `activate(envelope)`, `closeAuthority()`, and `close()`; no signing operation or private key is provided by the wrapper.

From the Pol.is clone root, using the installed Node 26 runtime:

```sh
node --test deploy/fncp/activation-foundation/*.test.mjs
```

The model tests create only new temporary ledgers and loopback listeners. They remove those exact generated files/listeners afterward. `synthetic-fixtures.mjs` generates ephemeral invented signing keys for tests; it is not a production or Dean-owned signing authority.

When the dedicated Pol.is stack is already running and **no coordinated backup is in progress**:

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/activation-foundation/real-origin-smoke.mjs
```

The actual-origin test uses new temporary access/authority stores and a new invented account. It records one synthetic vote and terminal revocation in the existing disposable Pol.is database, removes only the allowlist entry it allocated, and retains the synthetic vote/tombstone as test history. It does not reapprove the three persistent WordPress fixtures, use their browser sessions, send a message or activate a public round. Output is aggregate-only; configuration values, credentials, XIDs and tokens are not printed. Its private generated report goes under `deploy/fncp/evidence/`.

## Important limits

1. The standalone browser/WordPress startup remains the legacy **fixture-only** proof. The later [integrated journey](../integrated-journey/README.md) and [WordPress registration journey](../wordpress-identity/README.md) connect this controlled wrapper to signed-synthetic identity and actual local provider operations. They do not convert the mailbox simulator into real sign-in or establish production OIDC-to-vote integration.
2. An operation already dispatched to Pol.is may commit before a lease expires or a closure is observed. The response is withheld and later dispatches are denied; an accepted vote is not undone and must not be automatically retried. An HTTP close is serialized behind prior operations in the existing one-process queue. This is not distributed instantaneous cancellation.
3. A full VM/process/memory snapshot rollback, trusted time, multi-instance coordination, signer custody/rotation, a production recovery authority and a permanently separated operator approval path remain unproven. Runtime configuration hashes are not a substitute for a reviewed release.
4. The earlier three-store checkpoint did not include this authority ledger. The later [four-store recovery](../expanded-recovery/README.md) includes it and starts the recovered access/activation service closed, rejecting its genuine old signed grant. This does not establish full restored-application operation, real identity/signing-secret custody or production disaster recovery. Production recovery must force fresh reauthorization and cover those separate lifecycles.
5. The 15-statement manifest remains a declared binding here. Actual engine fixed-statement/direct-route checks and image security results are separate evidence; passing this verifier does not clear vulnerabilities or authorize publication.

## Primary references

- [Official Pol.is self-hosting/source](https://github.com/compdemocracy/polis) and [configuration](https://github.com/compdemocracy/polis/blob/edge/docs/configuration.md): upstream engine/deployment basis.
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html): identity is separate from application approval and activation; see the adjacent identity package for the implemented protocol profile.

This signed activation protocol is Barayamal-specific local work, not a feature supplied or certified by Pol.is. Production and participant testing remain HOLD.
