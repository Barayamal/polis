# Production WordPress bridge V1 contract

This new package is separate from every synthetic-only adapter. It remains disabled without explicit private configuration. No existing WordPress site or registration store is adopted. The BFF retains the actual production principal and uses only `createParticipantIdentityBoundary(...).current(principal).accountId`; request data never selects accounts, issuer, mapping functions, deployment or conversation. Only the BFF sees the opaque account; public registration responses expose a UUID reference. Email, issuer subject, Pol.is XID and tokens never enter this contract.

## Configuration

`FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE` in private wp-config names an absolute, canonical private JSON file. Exact keys:

- `profile`: `FNCP_PRODUCTION_WORDPRESS_V1`.
- `deploymentId`, `conversationId`: fixed 1–128 ASCII letters/digits/underscore/hyphen.
- `wordpressOrigin`: canonical HTTPS origin, no trailing slash, credentials, query or fragment.
- `eventEndpoint`: fixed canonical HTTPS URL ending exactly `/internal/wordpress/events`.
- `consentVersion`: reviewed ASCII identifier; `noticeSha256`: lowercase SHA-256 of the reviewed notice bytes. The plugin does not invent or change consent language.
- `serviceRequestKey`, `serviceResponseKey`, `eventKey`: three distinct base64url-without-padding encodings of 32 random bytes. **Decode to bytes before HMAC.** They are independent of identity mapping, invitation, activation, gateway, database and WordPress salt keys.
- `caFile`: absolute canonical file containing only reviewed CA certificates for the event receiver. Missing/unreadable trust material fails closed. Never disable certificate or hostname verification.

Native WordPress operators require explicit `fncp_manage_registrations` capability, their normal logged-in session and an action-specific WordPress nonce. Installation does not assign capabilities. BFF account identity is not a WordPress operator role. WordPress must receive genuine HTTPS at its trusted listener; this plugin never trusts caller `X-Forwarded-Proto` to establish TLS.

## Service requests

Only POST to `/wp-json/fncp/v1/register` or `/wp-json/fncp/v1/status`. Content-Type must be `application/json`, no query, browser cookies, Origin or browser fetch metadata. Maximum raw body 8192 bytes. All object keys are lexicographically sorted recursively, UTF-8 JSON without whitespace, unescaped slashes/unicode. The PHP checker requires those canonical bytes, rejecting duplicate keys and ambiguous encodings.

Headers:

- `X-FNCP-Timestamp`: ten-digit Unix seconds, at most 30 seconds from the server clock.
- `X-FNCP-Signature`: `sha256=` plus lowercase hex HMAC-SHA256 of `FNCP_WP_REQUEST_V1\n` + action (`register` or `status`) + `\n` + timestamp + `.` + exact raw body, using decoded `serviceRequestKey`.

Register body exact keys: `schemaVersion:1`, `deploymentId`, `conversationId`, `receiptId` (lowercase UUIDv4), `accountId` (`acct_` followed by43 base64url characters), `consentVersion`, `noticeSha256`, `adultSelfAttested:true`, `eligibilitySelfAttested:true`, `registrationConsent:true`, `issuedAt`, `expiresAt`. Times are integer seconds; issuedAt is not future; lifetime1–60 seconds. New insertion requires unexpired claims. An exact committed receipt/account/full-body retry returns the original reference even after claim expiry, but requires fresh request authentication. Reusing receiptId with different bytes or another receipt for the same account fails. The BFF durably retains its original request before the first call. Receipt grants no access or eligibility verification.

Status body exact keys: `schemaVersion:1`, `deploymentId`, `conversationId`, `accountId`, `nonce` (43 base64url characters generated fresh for this call by BFF). Status is service-only and may return a rightful account's prior reference after an uncertain registration. It never creates/adopts a new registration.

## Responses

HTTP200 only for success. Response is exact `{payload,signature}`. Payload is base64url canonical JSON; signature is lowercase hex HMAC-SHA256 using decoded `serviceResponseKey` over `FNCP_WP_RESPONSE_V1\n` + action + `\n` + payload. BFF verifies response signature and exact schema, deployment/conversation/account or receipt and nonce. Reject every non200, redirect, cookie, unsigned response, mismatch, oversized or late response. The BFF rechecks its live principal, session deadline, clock and activation around awaited work.

Register payload exact keys: `schemaVersion:1`, `deploymentId`, `conversationId`, `receiptId`, `registrationId` (UUIDv4), `status:'SUBMITTED_NOT_APPROVED'`. This is submission receipt status, not current approval status; query status for current decisions.

Status payload exact keys: `schemaVersion:1`, `deploymentId`, `conversationId`, `accountId`, `nonce`, `registrationId` (UUIDv4 or null), `state` (`unregistered`, `pending`, `approved`, `revoked`), `version` (0,0,1,2 respectively), `decisionEventId` (UUIDv4 for decided states, null otherwise), `deliveryPending` (boolean), `observedAt` (integer Unix seconds). A durable revocation is immediately reported as revoked/version2 even if delivery failed. Pending registration is not approval. Approved+deliveryPending may be reconciled only when the access store independently proves this same event/version applied; deliveryPending never creates a grant.

Errors are unsigned generic `{error:'registration_unavailable'}` with400/403/409/503. No database errors, keys, raw receipts, identifiers or response bodies go to application logs. A client must not infer whether an uncertain operation committed from a failed HTTP exchange.

## Decision and outbox

At most20 lifetime registrations for the one configured deployment/conversation; revocation does not free a slot. Initial state pending/version0. Approval is version1; revocation from pending or approved is always version2 and terminal. Repeated identical decisions reuse the immutable event. At most40 events total; this follows from20 accounts × two decisions, so terminal removal does not compete with unrelated journal capacity.

An event has exact fields: `schemaVersion:1`, `eventId` UUIDv4, `deploymentId`, `conversationId`, `registrationId`, `accountId`, `version`1|2, `state`approved|revoked, `occurredAt` integer Unix seconds. Decision/version and canonical immutable raw event body commit in one database compare-and-swap. Transport starts only after durable commit. Retry preserves exact body/eventId/version, signs a fresh timestamp, disables redirects and verifies TLS. Headers `Content-Type: application/json`, `X-FNCP-Timestamp`, `X-FNCP-Event-ID`, `X-FNCP-Signature` (`sha256=` + HMAC of `FNCP_WP_EVENT_V1\n` + timestamp + `.` + exact body, decoded eventKey). Body size≤8192; receiver must bound request lifetime and reject stale timestamps.

Only HTTP200 with exact JSON `{ok:true,eventId:<same>,version:<same integer>}` acknowledges delivery. A lost ACK, timeout or failed metadata save remains uncertain/pending. Late failed attempts cannot undo a prior ACK. Explicit operator retry prioritizes revocations; no registration, approval, retry or plugin activation sends invitations, email or public messages.

The access writer durably inserts the pending event/deny barrier before awaited provider effects, reconciles identical replay, rejects conflicting ID/version and wrong binding, ignores old approvals and preserves terminal revocation across crashes. Provider removal may complete later. **There is no cross-store atomicity claim.** The BFF must make nonce-bound fresh status checks before/after protected effects, never authorize from an old approved cache, and close on transport, time, configuration, storage or replay uncertainty. A status check is not a lock spanning an external vote; define the protected operation's authorization point and retain any ambiguous outcome without blind replay.

## Storage and recovery

The new non-autoloaded `fncp_production_wordpress_v1` option holds the complete bounded registry, outbox and a configuration digest. Read authority directly from SQL; use `BINARY option_value` compare-and-swap and invalidate the options cache after writes. Do not use a cached option value, PHP process lock or WP-Cron as cross-worker authority. Each operation validates state and persisted clock high-water; invalid/backward time permanently records clockClosed and denies further grants. Recovery preserves registrations, consumed receipt IDs, immutable decisions, outbox and terminal tombstones with matching keys/configuration. New service sessions/principals/activation are required; restoring data alone never opens participation.
