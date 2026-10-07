# Barayamal participant service

This separate participant service uses Pol.is for statements, native votes and analysis, and WordPress for staff approval and durable revocation. Its normal entrypoint is `main.mjs`; the older synthetic entrypoints remain separate.

The implementation supports one conversation, fifteen fixed statements and twenty lifetime registrations. Registration includes three explicit self-attestations. Staff approval, an account-bound one-use invitation, a current identity and a current signed activation are all required before participation. Revocation is terminal and does not free a registration slot.

## Normal process

```sh
node --max-old-space-size=384 deploy/fncp/production-service/main.mjs /run/fncp/service.json
```

The container uses UID1000, immutable source, an owned private material directory and a separate persistent SQLite state volume. See `../production-deployment/COMPOSE.md` for the eight-role composition and exact file contract. The process starts with admission closed. An empty volume does not provision an installed deployment.

`service.mjs` reads an exact JSON manifest and captures each material file through an owned, non-following file descriptor. It rejects duplicate key roles, private activation signing keys, mismatched origins and changed files. A periodic custody check closes admission and drains the process if material, clock or listener health changes. Restart clears browser sessions and live capabilities, consumes outstanding invitations and requires a fresh activation for the new boot.

| Module | Responsibility |
| --- | --- |
| `browser.mjs`, `public/` | Native HTTPS, sign-in redirect/callback, Secure HttpOnly cookies, same-origin CSRF checks, registration/status, invitation redemption and voting UI |
| `access.mjs` | One SQLite writer, current identity/approval/activation checks around awaited effects, durable receipt and event ordering, capacity and revocation |
| `wordpress-bridge.mjs` | Fixed native HTTPS registration/status calls, independently keyed request and response authentication |
| `event-receiver.mjs` | Bounded native HTTPS WordPress event ingress, canonical body/HMAC/freshness checks, exact acknowledgement and drain |
| `operator.mjs`, `operator-cli.mjs` | Private Unix socket for status, challenge, activation, admission, invitations and recovery descriptor; no operator HTTP route |
| `custody.mjs` | Private file capture, continuous custody checks and exclusive service ownership |
| `store-schema.mjs`, `store-validation.mjs` | Persisted schema, index and complete semantic validation before opening an existing store |
| `recovery.mjs` | Offline copy/reseal of a closed access store under a fresh recovery epoch; never a substitute for joined backup |

Identity comes from the separate `production-identity` adapter. Only its actual live principal objects can authorize access. The separate `production-provider` adapter talks to fixed private Pol.is HTTPS routes; it does not expose gateway credentials, provider credentials or native participant tokens to the browser. `production-activation` verifies offline Ed25519 envelopes and retains sequence and replay history across boots.

## Operator workflow

1. Inspect the installed source/images, private material, fixed content and native closed round.
2. Start the normal services and read `status` and `challenge` through the private operator socket.
3. Review the challenge and sign it outside the running participant image with `../production-activation/offline-sign.mjs`. The challenge binds the logical deployment, conversation, source, eight images, configuration, seed, provider, recovery epoch, boot and sequence.
4. Supply the signed envelope through the operator CLI's standard input. Activation alone does not admit participants.
5. Open the native conversation through the reviewed maintenance operation, then explicitly admit the participant service. Native conversation opening and participant admission are separate operations; do not assume one performs the other.
6. WordPress staff review pending registrations using their ordinary authenticated session, custom capability and action nonce. The immutable outbox retries only the recorded event; approval is acknowledged after provider upsert and matching readback. Match the participant's registration reference with the WordPress row, then use the private `invitation-for-registration` command; the service resolves its account internally and issues only against its current approval and sign-in.
7. Before maintenance, close participant admission, close the native conversation, drain the participant and WordPress services, and stop the databases cleanly. Preserve all stores and replay history together.

The CLI accepts only its documented commands and a private state directory. Invitation tokens and signed envelopes are private operator data. No command sends invitations or email.

## Registration-reference invitation handoff

The rightful signed-in participant sees `registrationReference`, the immutable
UUID of their committed WordPress registration. It is null before a confirmed
registration and after sign-out. It is a support/matching reference, not a
credential, proof of eligibility or authority to select an account. The browser
cannot submit it to select another participant. Account IDs, Pol.is XIDs, email,
provider subjects and invitation tokens remain absent from public status.

After WordPress approval is acknowledged, the participant must remain signed in
with the approved account. The operator passes the exact private input
`{"registrationId":"[that registration UUID]"}` through standard input to:

```sh
node deploy/fncp/production-service/operator-cli.mjs /var/lib/fncp invitation-for-registration
```

Use this only through the reviewed owner-only operator access. The command
returns an invitation token and millisecond expiry solely to the private
operator. It resolves the existing registration inside the service and retains
the same live identity, applied approval, fresh signed WordPress status, active
deployment and open-admission checks as account-bound issuance. An unknown,
pending or revoked reference, missing/expired sign-in, closed round or uncertain
WordPress response cannot issue a code. The older private `invitation` command
remains available for established tooling that already holds its account ID.

The local workflow prepares a manual handoff, not automatic sending. Once
correspondence is separately approved, provide the configured entry URL and the
fresh code privately to the intended participant, with its exact expiry. Do not
embed the code in a URL, put it in a saved draft, transcript or evidence pack, or
read/export the database to discover its account mapping. The participant pastes
the code into the page without signing in again. Issuance and reissue return no
account ID, registration reference, email or XID.

Codes are one-use and last at most ten minutes or the current identity deadline,
whichever is earlier. Issuing a replacement consumes previous codes and
participation grants for that account. A new sign-in, logout, revocation,
admission closure or process restart also invalidates outstanding codes. If the
code expires or the participant signs in again, inspect their current approval
and obtain a new code through the same reference command; a reference never
reopens a revoked account. Nothing in this implementation sends a message or
approves real participant invitations.

## Ordering and uncertain results

Every protected operation checks the current principal, activation, round, approval and provider state before and after asynchronous work. A failed response does not establish that a registration or vote was absent: the UI shows an unconfirmed outcome and requires an explicit status check. It does not automatically repeat a vote or invitation redemption.

Revocation first persists a terminal local denial and consumes outstanding invitations. Provider removal and version-two readback follow. A delayed version-one approval cannot clear that barrier. A failure leaves removal pending; it cannot restore participant access. Existing stores with inconsistent account/event/receipt histories, unknown schema changes, storage faults or backward clocks reject startup.

## Recovery

`recoverClosedProductionAccess()` accepts a source and new target SQLite path plus verified source/target descriptors. Both namespaces must be stopped. It refuses existing targets, ownership locks, sidecars, changed authority, changed credentials, changed endpoints and changed content. It preserves every account, event, invitation and clock value, changing only the binding digest for the new recovery epoch and actual target configuration hash. Normal service startup independently checks that digest.

This helper copies only `access.sqlite`. PostgreSQL, MariaDB, the activation ledger and exact private material must be recovered together by the deployment recovery workflow. It never resets the activation replay floor, opens admission or authorizes a release. A thrown recovery result remains unconfirmed and must not be adopted.

## Validation and release boundary

Source tests use invented identities and fresh private files. Separate browser-engine tests exercise the UI. Separate native WordPress/MariaDB/Pol.is tests exercise signed registration, approval, a native vote, terminal revocation and persistence. The native vote is independently checked in PostgreSQL against the expected participant and statement; an HTTP response alone is insufficient evidence.

Delivered evidence must identify the exact source and image subjects tested. A simulator result does not establish compatibility with a chosen external OIDC provider, public domain, hosting environment or production staff account. Full normal composition and joined restore are separate acceptance checks. See the accompanying implementation report for their actual outcomes and remaining release decisions.

This is a Barayamal customization. The upstream basis remains the [Pol.is Docker self-hosting instructions](https://github.com/compdemocracy/polis/blob/stable/README.md), [configuration guidance](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md), [math worker](https://github.com/compdemocracy/polis/blob/stable/math/README.md) and [HTTPS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md).
