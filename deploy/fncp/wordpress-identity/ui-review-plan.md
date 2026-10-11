# Seamless synthetic registration UI and expanded recovery — review plan

Read-only architectural review of the existing public assets, BFF, private issuer driver, WordPress client and strict recovery contract. This plan is not a test result or authorization to operate an authenticated browser. No runtime was started for this review.

## Smallest useful participant interface

In seamless registration mode, separate these states instead of treating every authenticated account as ready to redeem an invitation:

1. Visitor / synthetic sign-in pending, with a visible cancel action.
2. Signed in, not registered: show the fixed `synthetic-registration-v1` notice and three **unchecked**, separately labelled declarations.
3. Registration request in progress: prevent double submission and keep a clear status message.
4. Registered, awaiting a separate local administrator decision: show the opaque registration reference, but do not say approved, heritage-verified, invited or eligible to vote.
5. A separately authorized invitation/participation path. Registration success must not itself display a usable invitation or open the round.

The current assets still contain manual callback and invitation password controls, and show the invitation form for the general authenticated phase. Do not describe that existing screen as the finished seamless registration UI. A strict seamless mode should not require the person to paste a WP challenge, receipt, callback, fixture or token. Legacy test modes may remain separate and accurately labelled.

The browser-facing registration request should contain only the exact three booleans and fixed notice version. The BFF obtains and retains its own per-session WordPress cookie, CSRF, challenge and receipt; it uses the fixed fresh local WordPress origin. Return only the registration result/reference and ordinary BFF state. The public session response must not expose the private WP handoff state.

## Priority negative tests

| Layer | Cases that matter |
| --- | --- |
| Public request schema | Missing checkbox, `false`, string `"true"`, number, array, extra fixture/email/XID/receipt/challenge/URL field, wrong notice version; all denied before WP mutation |
| Authentication | Visitor, pending OIDC, expired principal, expired browser session, stale fixture-auth capability, logout/account change during each bridge await |
| CSRF and sessions | Missing/stale CSRF, old rotated cookie, duplicate cookie, cross-origin and same-site-but-different-port request, forwarded result/session between two accounts |
| Private WP client | Separate cookie/CSRF jar per BFF session/flow; never share a mutable singleton across users; reject unexpected redirects, cookie scope/name, malformed JSON, oversized bodies and wrong mode/reference schema |
| One-use behaviour | Concurrent submit, refresh while pending, double click, lost reply after WP commit, retry after timeout, WP cookie rotation; at most one immutable registration and no caller-selected replacement identity |
| Expiry during transport | Expire at WP session fetch, challenge fetch, receipt signing and registration acknowledgement. Do not expose a stale result as current authority; acknowledge that a completed WP registration cannot be rolled back by suppressing its response |
| Failure recovery | If WP may have committed but response is lost, show an uncertain outcome and do not automatically resubmit. A read-only reconciliation path, if supplied, must use the original private flow and return only that account's result |
| Approval separation | Registration succeeds but invitation/participation still fail without acknowledged WP approval, live identity, signed activation and open round; no automatic provider upsert from registration |
| Logout/revoke | Clear pending private bridge state and UI declarations on logout. A detached already-issued receipt has its documented short lifetime; local UI logout must not be falsely represented as remotely undoing a WP registration |
| Projection | `/api/session`, registration response, DOM, errors, URLs, logs and browser storage never contain WP cookies/CSRF, challenge, receipt, principal, fixture, XID or upstream token |

The private bridge needs a stable per-flow result or an explicit uncertain terminal state. A BFF-only `registered=true` bit is not independently current WordPress approval, and a browser refresh must not silently reset an uncertain committed registration to a fresh submission.

## Testable UI without secret controls

Use three explicitly different evidence layers:

- **Protocol integration:** the existing private Node client owns its invented cookie/CSRF jar and uses the signed synthetic issuer driver. Exercise actual BFF/WordPress/receiver HTTP without rendering or touching a user's browser. This is the best place for concurrent claims, session rotation and transport-failure assertions.
- **DOM interaction tests:** execute the shipped `app.js` against an isolated test DOM or narrow element stubs with a fake fetch transport. Assert initial unchecked state, exact submitted booleans/version, disabled busy controls, one request on double click, `textContent` rendering, status/focus behaviour, cancel/logout cleanup, 401/403 return to visitor and an uncertain-outcome warning. Label this DOM/model evidence, not rendered-browser or accessibility certification. Do not add a browser route that returns a fixture-authenticated state merely to make the DOM test easier.
- **Rendered shell inspection:** use the in-app browser only within the permitted non-secret local preview scope. Inspect layout, labels, focus affordances and the closed/synthetic notice. Stop at restricted login/credential interaction rather than populating password/callback/token fields, changing cookies through hidden browser state or switching to broader computer control. Authenticated rendering is a separate explicitly permitted check; neither protocol tests nor static preview prove it.

A browser-cookie helper is not an acceptable shortcut around the login/credential boundary. If a synthetic browser journey is later explicitly permitted, the application should set/rotate its own HttpOnly cookie through normal same-origin responses. Test tooling should not manufacture an authenticated browser cookie or inject an internal principal into page state.

## Private operator injection, if implemented

Keep synthetic subject selection out of every browser HTTP route. The existing in-process driver is sufficient for automated protocol tests and needs no additional listener.

For a separately permitted interactive proof, a narrow private operator channel can complete an **already-existing exact pending flow**:

1. Browser starts only an empty-body, CSRF-protected pending check; the BFF creates the binding. No browser-supplied subject, principal, email, callback or signer is accepted.
2. An in-process operator method or mode-0600 Unix-domain socket selects that exact pending flow. Do not infer the intended browser from a global `lastBinding` when multiple flows exist. Reject ambiguous selection; a non-authoritative display correlation label may help the operator without becoming an auth token.
3. The operator injects one invented issuer response and completes real signature/state/nonce/PKCE validation privately. Recheck the same pending object, expiry, cancellation and generation after awaits. Keep the verified pending principal in server memory, with no callback/credential in stdout or files.
4. A same-origin, cookie-and-CSRF-protected empty-body POST consumes that ready result once, then sets the normal rotated browser cookie/CSRF. A GET or polling status request must not create authentication. Cancellation, logout, replacement start and shutdown invalidate the pending result.
5. The operator interface returns only a bounded acknowledgement. No public subject-login endpoint, token return, arbitrary execution command, remotely reachable TCP port or automatic identity grant on page visit is introduced.

This is an architectural option, not permission to automate a login page. When the required browser interaction is disallowed, finish protocol/DOM checks and report the rendered-authenticated gap.

## Expanded actual recovery: additions beyond the current model

The current `strict-recovery/contract.mjs` verifies access/activation stores plus supplied WP event/provider metadata. It does **not** cover the new WP registry, challenge/receipt state, two new signing roles or private BFF-to-WP sessions. The earlier coordinated restore likewise cannot be cited as assurance for these additions.

Before a new actual proof, the expanded contract/observer should cover:

- Exact source context, project labels, image IDs, fresh synthetic WP/MySQL source, strict access SQLite, activation ledger and disposable Pol.is PostgreSQL. Establish coordinated quiescence independently; observed memory/capability counts must not merely be hard-coded to zero.
- Exact WordPress registry and approval-outbox values, including immutable registration IDs, fixture/round uniqueness, all three true self-attestations, consent version, `acceptedAt`/`createdAt`, and the corresponding mapped strict identity. Compare private contents/hashes, not just equal counts. Latest acknowledged outbox decisions must equal applied access events and terminal provider tombstones for the same mapped identities.
- Explicit policy for guest cookie/CSRF sessions, pending challenges, unconsumed receipts and server-side bridge capabilities. Restored services start closed with no revived volatile authority. Preserve required one-use/tombstone evidence and invalidate old guest/bridge sessions; do not silently discard replay history to make the restore pass.
- The existing identity-mapping key and activation/event/provider keys, plus the WP challenge and BFF registration signing roles. Record independent fingerprints and distinguish required stable mapping-key continuity from any deliberately rotated ephemeral handoff authority. Fingerprint agreement alone does not prove effective-key possession or safe custody.
- New boot/recovery binding and retained activation sequence/replay floor. After isolated restore, old cookie/CSRF, pending challenge, signed receipt, invitation, participation token and activation envelope all remain unusable; a fresh local session cannot revive a terminally revoked mapping. Never reopen the round to claim success.
- Authenticated encrypted components, separately protected key material and a signed exact component manifest. Missing/swapped components, tampered bytes, wrong schema/key/epoch, partial acknowledgement, restored older registry against newer access state and lost receipt-consumption history must fail closed in isolated negatives.
- Restore only to newly identified containers and fresh file copies, never source paths/volumes. Verify source preservation before/after; stop/remove only proof-owned targets after positive ID checks. Retain private failed-run artifacts and report incomplete cleanup honestly.

An actual restore report must distinguish byte/content equivalence, schema verification, aggregate invariants and behavioural denial tests. A matching row count, a model manifest or a new closed boot alone is not evidence of full four-store recovery correctness. Real identity, participant eligibility, production browser security, live delivery and public launch remain outside this synthetic proof.
