# WordPress → local approval receiver

**Synthetic local proof only. Not a deployed WordPress integration or a live voter service.**

This small plugin gives a disposable local WordPress administrator an approval and
revocation screen. It deliberately does **not** use Jetpack, existing registration
forms, participant emails, names, heritage information, uploads, production sites,
or any historical source records. It never sends email, SMS or a public message.

## Installation in the disposable instance only

1. Copy or link this directory to the disposable WordPress `wp-content/plugins/`
   directory as `fncp-wordpress-local`. Do not install it on Barayamal's live site.
2. In that instance's private `wp-config.php`, set `WP_ENVIRONMENT_TYPE` to `local`,
   `FNCP_WP_SYNTHETIC_ONLY` to the boolean `true`, and
   `FNCP_WP_LOCAL_EVENT_SECRET` to the independent randomly generated receiver key.
   Use 32–256 printable non-space ASCII characters; keep this key out of Git,
   screenshots, logs and browser code. It must not reuse the Pol.is gateway key,
   provider key, WordPress salts or local administrator token.
3. Activate **FNCP Synthetic Approval Bridge (LOCAL ONLY)** in the disposable
   instance. No activation action contacts a server.
4. Start the separate local receiving adapter on **127.0.0.1:8101**. It must have
   the matching signing key and a pre-provisioned synthetic fixture registry.
5. Open **Tools → FNCP synthetic approvals** while logged into that disposable
   WordPress as an administrator. The sole round is `synthetic_round_local`.
6. Record approval of a pre-provisioned key such as `synthetic_wp_integration`.
   Only `synthetic_[a-z][a-z0-9_]{0,39}` is accepted; email-like strings are rejected.
7. Require the journal to show `ACKNOWLEDGED`, not just a successful form post.
   Until the receiver confirms, the decision is pending delivery.
8. Revoke the same fixture and verify denial in the separate access service. A
   revocation cannot be reapproved in this proof; use a new synthetic fixture.

The plugin has no configurable destination URL. Its only network request is a
POST to `http://127.0.0.1:8101/internal/wordpress/events`, with redirects disabled,
a three-second timeout and a 4096-byte response limit. WordPress and the receiver
must run on the same local host. Loopback HTTP is a bounded synthetic-test choice,
**not** production transport guidance.

## Wire contract

The exact raw UTF-8 JSON has these fields and no registration content:

```json
{
  "schema_version": 1,
  "event_id": "00000000-0000-4000-8000-000000000001",
  "subject": "synthetic_wp_integration",
  "round_id": "synthetic_round_local",
  "version": 1,
  "state": "approved",
  "occurred_at": "2026-09-13T00:00:00Z"
}
```

The example UUID/time are placeholders. Real local events use a random UUID v4
and UTC creation time. `state` is `approved` or `revoked`. Version is monotonic per
round/account; repeated identical decisions reuse the existing event.

Headers:

- `Content-Type: application/json`
- `X-FNCP-WP-Timestamp`: current Unix seconds, decimal string.
- `X-FNCP-WP-Event-ID`: the body's event ID.
- `X-FNCP-WP-Signature`: `sha256=` followed by lowercase hexadecimal
  `HMAC-SHA256(secret, timestamp + "." + exactRawBody)`.

Retries retain the exact body, event ID and version and sign a new attempt
timestamp. Receiver responsibilities: enforce clock skew ≤300 seconds, verify
signature with constant-time comparison, validate exact schema and fixture scope,
reject same-version conflicting events, make identical replay idempotent, and
never let an older approval override revocation. A successful delivery requires
HTTP 200 and JSON `{ "ok": true, "event_id": "<same>", "version": <same integer> }`.
A generic 2xx, mismatched ID/version or malformed response is not an ACK.

## Durability and limits

`fncp_wp_local_journal_v1` is a non-autoloaded `wp_options` record. Subject version,
decision and immutable event body are committed in one SQL compare-and-swap update
with a byte-exact prior-value condition. Contention retries from a fresh DB read.
Delivery metadata is persisted separately only after the network attempt. If the
receiver applies a request but the ACK/save is interrupted, replay of the same
event is safe only because the receiver implements idempotency.

The fixture journal is bounded to 20 round/account pairs and 200 retained events;
capacity exhaustion fails closed and does not purge evidence. Pending revocations
are retried before older approvals. Retry is a deliberate administrator POST with
a separate nonce—there is no cron or background notification loop.

**There is no cross-store atomicity claim.** If a revocation cannot reach the
receiver, WordPress can show a pending revocation while provider access still
exists. Close the local round while resolving it. Production needs a documented
fail-closed freshness/lease design plus deployment-wide closure assurance.

## Verification and interfaces

```sh
php deploy/fncp/wordpress-local/tests.php
php deploy/fncp/wordpress-local/plugin-boundary-tests.php
```

Those are isolated model checks, not proof that a real WordPress installation is
correct. After the disposable runtime and receiver have been provisioned, use
`integration-test.php` with the exact private bootstrap path documented there.
No test accesses the live WordPress site.

```sh
FNCP_WP_BOOTSTRAP="$PWD/deploy/fncp/local-wordpress-runtime/.runtime/wordpress/wp-load.php" \
  php deploy/fncp/wordpress-local/integration-test.php
```

The receiver must already register `synthetic_wp_integration` (or the fresh key
provided through `FNCP_WP_TEST_FIXTURE`). This one-shot test leaves that fixture
revoked and retains its two synthetic journal events. It refuses a fixture with
existing WordPress history instead of silently resetting it. If an attempt fails,
review its preserved journal and resolve any pending revocation before reusing
the runtime; use a different pre-provisioned synthetic fixture for a new test.

`FNCP_WP_AUTH_CHECK_ONLY=1` repeats only the actual WordPress role/nonce checks,
without any approval event. It creates or reuses a local subscriber named
`synthetic_wp_subscriber` with an empty email and a random undisplayed password.

The disposable test exercises actual WordPress capability and nonce checks plus
actual `wp_options` persistence and local receiver acknowledgements. It does not
by itself prove that browser cookies, the voter UI, email ownership, or every
Pol.is warm-session route works; those require the separate end-to-end checks.

Internal PHP interfaces for the disposable integration:

- `fncp_wp_local_journal()` returns `FNCP_Local_Journal`.
- `->change(round, subject, state)` persists a decision and returns its event record.
- `fncp_wp_local_deliver(journal, record)` attempts the fixed local request.
- `->snapshot()`, `->pending()`, `->deliveryResult(...)` expose local journal state.
- `fncp_wp_local_authorize('change'|'retry')` enforces mode, POST, capability and nonce.

Only authenticated `admin_post_...` hooks are registered; no public `nopriv`,
REST, registration or webhook-submission route is added. The page and both POST
handlers require `manage_options`; the handlers separately check WordPress nonces.

## Official technical guidance used

- [WordPress nonce security](https://developer.wordpress.org/apis/security/nonces/):
  nonces prevent some CSRF misuse but are neither authorization nor single-use
  replay protection. This plugin checks capability separately and uses durable
  event IDs/versions for receiver replay handling.
- [Administrator nonce verification](https://developer.wordpress.org/reference/functions/check_admin_referer/).
- [WordPress HTTP POST API](https://developer.wordpress.org/reference/functions/wp_remote_post/):
  the plugin uses a fixed code-owned destination and does not disable TLS checks.
- [Prepared SQL placeholders](https://developer.wordpress.org/reference/classes/wpdb/prepare/):
  journal values are bound, not concatenated into SQL.
- [Explicit environment type](https://developer.wordpress.org/reference/functions/wp_get_environment_type/).
- [Option creation](https://developer.wordpress.org/reference/functions/add_option/).

This is Barayamal's local adapter code, not an upstream Pol.is or WordPress
endorsement. Real authentication, owner-approved eligibility administration,
private deployment, operational custody and launch approval remain separate.
