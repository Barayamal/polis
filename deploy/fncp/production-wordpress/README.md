# Production WordPress registration bridge

This is a new plugin and private service contract. It does not relax the earlier synthetic adapters or activate a WordPress site. Its code implements immutable account registration, separate native WordPress operator approval, terminal revocation, durable signed event delivery and nonce-bound current status. See [CONTRACT.md](CONTRACT.md) for the exact Node/PHP wire and configuration.

The participant service must supply an account from its actual production identity boundary. The plugin receives no participant email, issuer subject, Pol.is XID, voting token or browser cookie. It retains the opaque account privately with a registration reference and the three agreed declarations. Those declarations are self-attestation and consent, not verified eligibility, adulthood or Indigenous heritage.

## Installation contract

Provision a separate owned WordPress/MariaDB service and reviewed source/image closure. Copy `contract.php`, `store.php` and `fncp-production-wordpress.php` together to its plugin directory; retain the package's license/provenance with its enclosing repository. Do not copy old databases or install this on an existing live site as an implicit consequence of a test pass. No activation hook assigns roles, adopts state, sends events or opens participation.

Set `FNCP_PRODUCTION_WORDPRESS_CONFIG_FILE` only in that service's private wp-config. The referenced file must be readable, canonical, regular, not a symlink, mode0400 or0600 and at most16KiB. It contains the exact private JSON configuration described by the contract. The CA file must be a canonical readable regular certificate-only PEM bundle, at most64KiB, without group/world write access. Include PHP OpenSSL support. Persist the same keys/configuration across process restarts; an altered binding fails against the existing store.

Expose WordPress through genuine HTTPS with its configured Host at the trusted listener. Caller-supplied forwarded-protocol headers are not a TLS authority here. Keep its internal registration/status routes inaccessible to browsers and limited to the participant service; they still authenticate their exact raw request bodies independently. Configure network policy so this plugin can reach only its reviewed HTTPS event endpoint. Its HTTP call explicitly verifies TLS, uses the configured trust bundle, disables redirects/cookies/compression, caps the response to4096 bytes and bounds each attempt to3 seconds.

The native operator uses the ordinary WordPress login flow. Assign `fncp_manage_registrations` deliberately to the approved operator role during provisioning. The plugin grants no capability itself. Tools → Registration decisions requires the capability; each decision/retry POST independently requires that capability, its action nonce, exact HTTPS origin and server-side reference lookup. WordPress staff login/MFA and chosen role assignment still need deployment-specific validation. Participant OIDC identity grants no staff capability.

WordPress's documented [nonce behavior](https://developer.wordpress.org/apis/security/nonces/) requires independent capability checks; its nonces are reusable CSRF tokens. The configured HTTP controls use documented [WP_Http request arguments](https://developer.wordpress.org/reference/classes/wp_http/request/). Absent request headers return null in [WP_REST_Request::get_header](https://developer.wordpress.org/reference/classes/wp_rest_request/get_header/); boundary tests cover this actual API shape.

## Durable behavior and limits

One non-autoloaded SQL option stores20 lifetime registrations and at most40 events. Direct SQL reads and byte-exact compare-and-swap updates make capacity, duplicate receipt consumption, decision version and outbox insertion one mutation across PHP workers. The store validates its schema and bindings before every operation. A failed/contended write does not grant approval. At most12 contention retries occur before failure. The approved reference is immutable; there is no email linking, account reassignment, deletion or slot reuse.

Registration starts pending/version0. Approval is version1; revocation from either pending or approved is always version2 and terminal. Repeated same decisions reuse the same event bytes. A revocation immediately appears in signed current status, including when transport remains pending. Receiver handling must persist a local deny barrier before awaiting provider removal and reject stale or conflicting approvals. Outbox ACK alone is not current approval freshness.

Exact registration retries remain idempotent after their claim expiration once the original receipt committed, with fresh request authentication. A new expired receipt never inserts. The BFF must persist its original canonical request before sending, and resolve uncertainty using the same request or fresh rightful-account status—not a newly invented receipt. Neither successful registration nor approval sends an invitation.

Retries are explicit operator POSTs; one handles at most four events, with revocations first. The rows remain pending when a request, ACK or metadata write is uncertain. An ACK cannot be downgraded by a late failed retry. Retry scheduling can later call the same bounded operation from an owned worker; do not infer delivery deadlines from page-driven [WP-Cron](https://developer.wordpress.org/plugins/cron/).

The durable store records observed time at millisecond precision. Backward, invalid or throwing clocks mark terminal closure; correcting time or restarting a PHP worker does not reopen it. There is no reset endpoint. Administrative recovery of a closed store requires the reviewed closed restoration procedure, diagnosis and a new activation; do not edit timestamps to manufacture validity. Database or configuration failures produce generic unavailable responses.

## Verification performed and still required

Run the source-only checks from the reviewed checkout:

```sh
php deploy/fncp/production-wordpress/tests.php
php deploy/fncp/production-wordpress/plugin-tests.php
php -l deploy/fncp/production-wordpress/contract.php
php -l deploy/fncp/production-wordpress/store.php
php -l deploy/fncp/production-wordpress/fncp-production-wordpress.php
```

The first suite has21 contract/model cases: lifetime slot and duplicate races, exact receipts, pending/approved/revoked transitions,40-event terminal capacity, ACK loss/late failure, signed current state, damaged state and durable clock closure. The second has11 WordPress API double cases: default closure, private files/trust, actual absent-header shape, HTTPS/header/Origin rejection, independent capability/nonce checks, registered-reference-only decisions, fixed bounded TLS calls, generic database failure and safe operator rendering. They create only a private temporary test directory and a fresh public certificate; no WordPress service, Docker engine, external website, actual operator account or participant record is used. Host runtime was PHP8.5.10.

These passes do not establish actual WordPress/MariaDB SQL isolation, web-server HTTPS handling, receiver integration, real staff login or browser participation. Next run the same contract against the new exact images, with real simultaneous PHP workers and real SQL: last slot, duplicate receipts, approve/revoke contention, shutdown after commit/before transport, lost ACK and receiver restart. Verify PHP→Node HMAC/canonical vectors, wrong CA/hostname/redirect rejection, service outage while warm participation is attempted, and true native capability/nonce failures. Then exercise joined restoration retaining immutable receipts, decisions and pending removals while all sessions and activation remain closed.
