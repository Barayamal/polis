# Local approval → invitation → Pol.is proof

**SYNTHETIC ONLY. NOT A LIVE PARTICIPANT SERVICE.**

This API harness adds a bounded, executable bridge to the existing Barayamal
Pol.is gateway and private conversation-scoped allowlist. It uses Node 26 built-ins
and SQLite, without npm installation. It is local code authored for this proof;
it is not an upstream Pol.is invitation feature. A separate [local WordPress plugin](../wordpress-local/README.md) and [browser service](../local-browser/README.md) now integrate with this API; see the [actual journey evidence](../LOCAL-C-JOURNEY-2026-09-13.md).

## What is implemented

**Later local reliability checks:** [shared request admission](ADMISSION-PROOF.md),
[signed receiver freshness/admission](RECEIVER-PROOF.md) and [graceful shutdown](LIFECYCLE-PROOF.md).
Stopping is not a provider round-close operation. In-flight side effects retain
their real or uncertain outcome; the code does not automatically replay them.

**Strict synthetic identity addition:** [the integrated journey](../integrated-journey/README.md)
sets `identityMode: 'verified-synthetic-oidc'` and supplies the same identity
foundation instance plus a mandatory signed activation guard. Its only identity
entry is private in-process `authenticateIdentity(principal)`. It requires a live,
minted principal and a verified Boolean issuer-email claim; neither grants round
approval. Stable opaque account/round mappings replace fixture passwords in this
mode. Fixture creation and the mailbox-simulator HTTP endpoint are unavailable.
Current applied WordPress approval is mandatory for invitations, redemption and
participation. Missing/mismatched identity mappings, expiry, logout, restart or
activation-generation changes invalidate capabilities. The legacy DB cannot be
opened in strict mode or vice versa; the integrated proof uses new stores only.

The older fixture-only mode and launcher role below are preserved. In the strict
test API, direct administrator approval may upsert provider state, but cannot
substitute for the required applied WordPress event or grant participation.
The new integrated positive proof uses signed WordPress events, not that exception.

- Persisted, conversation-bound approvals and opaque random XIDs.
- Explicit **simulated mailbox ownership** through synthetic fixture credentials.
- Single-use, expiring invitations bound to the authenticated synthetic account;
  a different account cannot redeem a forwarded invitation even if it is approved.
- Stored hashes (not raw values) for fixture credentials, invitations and sessions.
- Local approval remains pending until Pol.is upsert and readback succeed.
- Every participation request checks current local approval, session lifetime and
  round state. Pol.is separately enforces its own live conversation XID allowlist.
- Revocation commits local denial and invalidates sessions/invitations **before**
  provider removal. Removal is retriable and verified; failed removal never restores
  local access. Reapproval after revocation is intentionally unsupported in this proof.
- Narrow bridge: participation initialisation, next statement and fixed-statement
  voting only. No submissions, uploads, reports, arbitrary routes or external URLs.
- Server derives XID and conversation identity. Caller tokens, cookies, query
  parameters, XID fields and authority headers are not forwarded to Pol.is.
- Local closure invalidates local sessions/invitations. It is explicitly **not**
  an implementation of deployment-bound, cross-store provider-wide closure.

## Prerequisites

1. A verified Node runtime including `node:sqlite`; local suites were run on Node 24.21.0 and 26.8.2.
2. The existing disposable Pol.is stack is running, its synthetic conversation
   bootstrapped, and the dedicated gateway/allowlist policies enabled.
3. `deploy/fncp/.env.staging` binds both policies to that same completed synthetic
   conversation. The harness reads this exact file internally and never prints it.
4. Direct provider origin is fixed to `http://127.0.0.1:5500`. No option accepts a
   different host, port, URL, proxy or remote service. The harness cannot be used
   to point to public Pol.is or existing live data.

## Run checks

From the repository root:

```sh
node --test deploy/fncp/local-access/access-server.test.mjs
```

These tests are labelled **model/fake-origin checks**. They test the local
authority and request boundary, not the real Pol.is implementation.

After the real disposable local origin is ready:

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/real-origin-smoke.mjs
```

The actual-origin smoke creates invented fixtures and approval rows, redeems an
invitation, submits one synthetic vote, tests forwarded-link/replay/expiry and
warm-session denial, then removes the XIDs allocated by this execution. It prints
only stage outcomes. The synthetic vote and operation tombstones remain in the
disposable Pol.is test database; it does not delete unrelated data or reset that
database. A cleanup failure returns nonzero and must be resolved before reuse.

## Start the independent local API

```sh
FNCP_LOCAL_SYNTHETIC_MODE=fixture-only node deploy/fncp/local-access/start.mjs
```

The API listens **only on `127.0.0.1:8099`**, and this entry point additionally starts the fixed signed WordPress receiver on `127.0.0.1:8101`. A new database starts closed. It creates
`local-access/.runtime/` (0700) with `admin.json` (0600) and `synthetic.sqlite`,
all ignored by this local directory's Git ignore. Runtime umask is 0077. Never
paste the credential file into chat, source code or terminal output. The randomly
generated administrator credential is separate from both upstream credentials.
Do not run multiple harness processes against one database: concurrency protection
is deliberately scoped to one local process. Stop with Ctrl-C; state survives restart.

This service remains API-only; the new browser UI is a separate service on 8100. No real email, SMS, outbound notifications, telemetry, registration upload or heritage evidence processing is implemented.
Browser Origin/Cookie/Sec-Fetch-Site requests are denied; expected Host and remote
address must match the loopback listener. This is not an internet security design.

## Signed local WordPress events

The separate receiver validates HMAC-SHA256 over timestamp + `.` + exact raw JSON, five-minute freshness, UUID, exact synthetic subject/round and version. It then uses the **same in-process serialisation queue/database** as API operations. Pending/revoked events deny access across restart; only applied approvals allow it. Conflicting identity/version fails, stale delivery is a no-op, terminal revocation cannot be undone. A maximum of 20 WordPress subjects and 200 ordinary event rows are allowed, with up to 20 reserved terminal revocations. This is not cross-service atomicity or a distributed lock.

`capture-mail.mjs` stores invented credentials/invitations only in private local files and sends nothing. `round-control.mjs` opens/closes only this synthetic gateway. See [the walkthrough](../local-wordpress-runtime/README.md) for exact commands. The startup helper detects receiver-port failure and closes the already-acquired API/database before exiting.

## API contract

All POST requests require exactly `Content-Type: application/json`, a JSON body
of at most 4096 bytes and the keys below. Unknown fields and all query strings
are rejected. Sensitive credentials belong in request bodies or Authorization
headers only, never in URLs, logs or version control. All responses are no-store.

| Endpoint | Authority | Exact body / result |
|---|---|---|
| `GET /health` | None | Clearly reports simulated mailbox, no real email and `productionReady: false` |
| `POST /test-admin/fixtures` | Admin bearer | `{fixture: "synthetic_alice"}` → fixture secret returned once to local caller |
| `POST /test-auth/mailbox-simulator` | Fixture secret | `{fixture, fixtureSecret}` → `fixtureAuthToken` for **simulated**, not verified, mailbox ownership |
| `POST /test-admin/approve` | Admin bearer | `{fixture}` → approved only after provider write/readback |
| `POST /test-admin/round` | Admin bearer | `{open: true/false}` → local gateway round state; closure invalidates local sessions/invitations |
| `POST /test-admin/invitations` | Admin bearer | `{fixture, ttlSeconds?}` → token in **local response only**; default 600s, max 900s |
| `POST /invitations/redeem` | Fixture-auth bearer | `{invitationToken}` → one `participationToken`, account-bound and single use |
| `GET /polis/participation-init` | Participation bearer | No body/query; synthetic Pol.is participant JSON with identity/auth material filtered |
| `GET /polis/next-comment` | Participation bearer | No body/query; next synthetic seed statement |
| `POST /polis/votes` | Participation bearer | `{tid: integer >=0, vote: -1/0/1}`; no free text, identity or extra fields |
| `POST /session/logout` | Participation bearer | `{}` → destroys that local participation session |
| `POST /test-admin/revoke` | Admin bearer | `{fixture}` → local denial first, provider removal + readback; safe to retry on failure |
| `GET /test-admin/status` | Admin bearer | Local open/closed and aggregate fixture/approval counts only |

Auth fixtures expire after 15 minutes and participation sessions after 30 minutes.
Returning within a valid session resolves to the stored opaque XID. A fresh
invitation can replace a session for an approved fixture; production returning-login
and lost-invitation recovery still need a real identity integration.

## Explicit limitations and next integration work

1. **No real mailbox verification or heritage verification.** The owner policy is
   self-attestation and round approval, not ancestry checks. This proof accepts
   only names matching `synthetic_*`, no participant emails or evidence documents.
2. **No genuine WordPress registration/account integration.** The separate local
   WordPress adapter now provides signed, scoped, replay-safe synthetic approval
   events. Production identity binding and distributed reconciliation remain.
3. **No production voter experience.** The separate local browser service now
   exercises these sessions end to end against Pol.is. It is fixture-only, not
   an authenticated production alpha-client integration.
4. **No atomic SQLite/PostgreSQL transaction.** Local failed-removal denial is
   tested, but production provider reconciliation, operation-outbox durability,
   in-flight distributed revocation and deployment-wide closure are outstanding.
5. **No production infrastructure/recovery assurance.** Synthetic PostgreSQL
   restoration was tested separately; coordinated recovery of WordPress, access
   state and Pol.is remains outstanding, as do production TLS, identity, sessions,
   rate limiting, account recovery, hosting sizing and all-inclusive costing.
6. **No production or launch approval.** Leave every public surface closed; no
   WordPress changes, real messages, purchases, cloud deployment or invitations
   are authorised by running a synthetic local proof.

Use the actual-origin smoke together with the existing gateway/allowlist tests.
Do not relabel passing model tests as upstream integration tests, or passing
synthetic integration as participant authentication or full launch assurance.
