# OIDC identity foundation — synthetic protocol proof only

This isolated package adds **no production login, mailbox verification service, eligibility decision, live callback, email/SMS, deployment or launch authority**. It does not modify the existing fixture-only browser/API guards. The self-hosted stack need not be running. All test identities use invented subjects and `.invalid` addresses. Protocol signing keys exist only in memory; the later TLS lab briefly generates its own test certificate/key in a fresh private temporary directory, removes those files immediately, and never changes global trust.

**Latest addition:** the [pure HTTPS redirect coordinator](HTTPS-REDIRECT-PROOF.md)
adds 70 checks without a signer, injection method, listener or default network
transport. A separate test-only `redirect-tls-lab.mjs` adds 25 actual TLS checks,
including authorization redirect plus token/JWKS exchange. The [BFF integration](../LOCAL-C-HTTPS-REDIRECT-2026-09-13.md)
uses a dedicated transaction cookie and shared principal authority. Logical
issuer/app sites are distinct and mapped only to loopback by the test client.
Cookie/navigation and app-script evidence is modelled, not a real browser-engine
or real-provider run. `SYNTHETIC_ONLY` remains mandatory.

**Earlier additions:** [independent response deadlines](DEADLINE-PROOF.md) add 25
tests and [actual loopback TLS token/JWKS transport](TLS-PROOF.md) adds 22. These
extend the original 48 protocol and 16 driver checks; all remain synthetic.
The TLS lab is a separate fixed adapter, not the original in-memory harness and
not a real provider or cross-site browser redirect.

**Later integrated increment:** `synthetic-browser-driver.mjs` now connects this
foundation to the strict local BFF/access path. Its 16 tests plus the original 48
protocol tests pass (64 total). `begin` returns only success; a private in-process
test driver must explicitly inject the invented response. Its one-use callback,
five-minute/128-flow limits, cancellation and race checks retain exact HTTPS
callback validation. The driver additionally requires fixed `.invalid` endpoints;
the foundation alone validates exact configured HTTPS URLs, not a `.invalid`
suffix. See [integrated journey](../integrated-journey/README.md).
That journey proves loopback cookie/CSRF and approval wiring; it does not turn the
synthetic issuer into a real provider or prove a real cross-site browser redirect.

## What is implemented

- Fixed, explicitly configured HTTPS issuer, authorization endpoint, token endpoint, JWKS endpoint and exact callback URI. No discovery, endpoint selection from browser input, redirects, ambient credentials, or default `fetch` transport. Only a caller-supplied `SYNTHETIC_INTERCEPT` transport is accepted; the supplied harness never opens a socket.
- Authorization-code flow through maintained `openid-client`, with fresh PKCE S256 verifier/challenge, state and nonce. The caller binds each login to its server-generated opaque browser-session ID. Pending transactions are capped at 128, expire after five minutes, and are consumed before callback processing or asynchronous exchange. Failed/uncertain exchanges require a new login; they are never automatically replayed.
- Required response issuer, state, nonce and ID token; explicit JWS signature verification through `enableNonRepudiationChecks`, fixed RS256 or ES256, issuer/audience/authorized-party validation, expiry and not-before checks. Extra audiences are denied unless trusted in server configuration, and multi-audience tokens require matching `azp`. Any supplied `azp` must match the client. This strict profile also requires a nonempty subject, integer timestamps, issuance within ten minutes, and token lifetime at most one hour; clock tolerance is zero.
- Only a frozen, instance-issued private principal leaves token processing. The identity is a keyed, domain-separated HMAC of exact issuer and subject—not an email, email hash, browser claim, or caller-selected XID. Round-scoped XIDs are separately derived from that opaque account pseudonym and round ID. Different issuers or rounds do not share identifiers. No raw issuer/subject/email/token is retained in the principal map.
- `emailVerifiedByIssuer` means only that the signed claims include Boolean `email_verified: true` and a nonempty email string. It is not proof of Indigenous heritage, present mailbox access, approval to vote, or a real-provider integration. Missing, false, string `"true"`, and numeric claims do not become verified mail claims. Email changes do not change the account identity.
- Generic error projections; upstream errors, malformed JSON excerpts, raw claims and tokens are never returned. Endpoint responses are JSON-only and limited to 64 KiB. In addition to the library timeout, each response has an independent five-second deadline covering headers and complete body, even when the adapter ignores abort. Cancellation is best effort and never blocks failure; late completions cannot revive a consumed callback. This is per response, not a five-second whole-login SLA. No redirect following or automatic retry policy is added. Principals expire at the earlier of ID-token expiry or fifteen minutes after verification. Restart invalidates pending flows and in-memory principal capabilities.

## Interface

`createIdentityFoundation(options)` is exported by `identity.mjs`. Configuration is server-owned:

```js
{
  mode: 'SYNTHETIC_ONLY',
  issuer: 'https://identity.example.invalid/',
  authorizationEndpoint: 'https://identity.example.invalid/authorize',
  tokenEndpoint: 'https://identity.example.invalid/token',
  jwksUri: 'https://identity.example.invalid/jwks',
  callbackUri: 'https://participant.example.invalid/oidc/callback',
  clientId: 'invented-client',
  signingAlgorithm: 'RS256', // or ES256; never negotiated from the token
  identityKey: /* server-owned 32–64 random bytes, not a string/password */,
  transport: { kind: 'SYNTHETIC_INTERCEPT', fetch: interceptedFetch },
  // Optional clientSecret: invented test secret; selects client_secret_basic.
  // Absent clientSecret selects a public client with PKCE (no client secret).
  // Optional trustedAdditionalAudiences: explicit server-owned string array.
  // Optional now: test clock for transaction/principal lifecycle only;
  // protocol JWT validation always uses the real system clock.
}
```

| Method | Result and boundary |
| --- | --- |
| `await begin({browserSessionId})` | `{ok:true, authorizationUrl}`. State, nonce and challenge are browser-facing protocol values; verifier remains private. The URL is returned, never opened. |
| `await complete({browserSessionId, callbackUrl})` | `{ok:true, principal}` or `{ok:false,error:'authentication_failed'}`. The callback is processed once. |
| `isVerifiedPrincipal(principal)` | True only for an unexpired object minted by this same module instance. A JSON copy or principal from another instance fails. |
| `participantXid(principal, roundId)` | Private `{ok:true,xid}` or generic failure. Does **not** allowlist, invite, approve or activate anything. |
| `publicResult(result)` | Minimal authentication/mail-claim summary with `eligibilityVerified:false` and `productionReady:false`. No principal, XID, account ID or tokens. |

The raw success result and `participantXid` output are private server interfaces, not HTTP response bodies. Use `publicResult` for an intentionally limited public projection. Do not log authorization/callback URLs, principals, tokens or private mapping keys. Authorize participation independently on every protected operation.

## Run and reuse the local protocol proof

From this directory:

```sh
npm ci --ignore-scripts --no-fund
npm test
npm audit --json
```

The install/audit commands contact the public package registry, not an identity provider. The original protocol tests replace global `fetch` with a throwing function. Their injected transport serves generated JWKS and signed tokens in memory, enforces the submitted code's S256 verifier and callback/client binding, and consumes synthetic authorization codes once. The later TLS tests use `openssl` on PATH and a fresh 127.0.0.1 HTTPS listener with explicit per-request trust; they independently verify listener shutdown. No external identity endpoint, browser, email, ambient cookies, global trust installation or Docker service is used by either suite.

Other local test modules can use the reusable harness:

```js
import { createSyntheticIdentityHarness } from './synthetic-harness.mjs';
const h = await createSyntheticIdentityHarness();
const result = await h.authenticate();
if (!result.ok || !h.identity.isVerifiedPrincipal(result.principal)) throw new Error('Denied');
const privateMapping = h.identity.participantXid(result.principal, 'synthetic_round');
// Keep privateMapping in the server-side test. It grants no participation.
const publicSummary = h.identity.publicResult(result);
```

For cross-module negatives, `authenticate({claims:{sub:'invented-other-subject'}})` creates a different principal; `email_verified:false` changes only the mail-claim flag. For callback lifecycle tests, combine `begin`, `h.authorizationResponse(authorizationUrl)`, and `complete`. The harness is test support, not an identity provider or production transport.

## Evidence and limits

Validation on 13 September 2026 with Node **26.8.2** / npm **12.0.2**: package protocol suite **48/48 passed**. Exact lock: `openid-client` **6.8.8**, `oauth4webapi` **3.8.8**, `jose` **6.2.12**. Scoped npm audit returned **0 known advisories** on that date for this isolated dependency tree only; this does not clear the rest of Polis or prove the code vulnerability-free. Node 22+ is declared by this package but this suite's reported execution used Node 26, not the stopped Docker stack.

The original 48-test suite covers real RSA/EC signatures, wrong key/algorithm/issuer/audience/azp/nonce, missing/expired claims, PKCE code substitution, forwarded callback binding, replay/concurrency, capacity/expiry, unknown fields, opaque identity mapping, secret/error redaction and malformed/redirecting upstream responses. That original suite does not test HTTPS/TLS; the separately documented later TLS lab does. None claims real-provider conformance, provider logout/revocation, production persistence, eligibility assessment or end-to-end production voting.

Before any real integration, the owner must approve a provider/client and registered HTTPS callback. A separately reviewed server adapter must supply secure random session cookies, login CSRF/origin protections, callback URL stripping and no-store responses, rotate the authenticated session, and preserve durable invitation/account/round-policy binding and warm-session revocation. Store the identity HMAC key securely with explicit backup/rotation/versioning: changing it changes account/XID mappings. Never silently fall back to email matching. No provider, account or deployment has been chosen or activated here.

## Polis compatibility and primary references

The existing upstream `server/src/auth/jwt-middleware.ts` validates OIDC tokens for its user path, then calls `create-user.ts`; that path includes `sub`/email-based mapping and claim-bearing diagnostics. This foundation deliberately does not reuse or modify that user-provisioning path for participant identity. A later approved integration must bridge the opaque principal into the dedicated participant gateway and its current allowlist, invitation, revocation and activation checks—not forward a raw OIDC token to upstream staff/user provisioning. Self-hosting Polis alone is not that integration.

- [Official Polis source and deployment instructions](https://github.com/compdemocracy/polis#-production-deployment) — upstream compatibility baseline, not a ready-made FNCP eligibility workflow.
- [OpenID Connect Core: ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation), [claim stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability), and [standard email claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
- [openid-client maintained source](https://github.com/panva/openid-client), [authorization-code grant](https://github.com/panva/openid-client/blob/main/docs/functions/authorizationCodeGrant.md), [explicit signature checks](https://github.com/panva/openid-client/blob/main/docs/functions/enableNonRepudiationChecks.md), and [intercepted fetch support](https://github.com/panva/openid-client/blob/main/docs/variables/customFetch.md).
- [jose maintained source](https://github.com/panva/jose) — synthetic JWK/key generation and real ID-token signing in the tests, also a locked upstream client dependency.

The provider-independent mechanism is implemented and tested locally. Production authentication and launch remain **not integrated / HOLD**.
