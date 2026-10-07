# HTTPS redirect coordinator — local synthetic protocol only

`https-redirect-driver.mjs` coordinates real authorization-URL and callback mechanics without a synthetic response injection method. It does not create a listener, certificate, cookie, signer, identity provider, network transport, registration approval or launch grant. Production remains `KEEP_CLOSED`.

## Interface and trust boundary

`createHttpsRedirectDriver({ mode: 'SYNTHETIC_ONLY', identity, authorizationEndpoint, callbackUri, now? })` returns a frozen object with `mode`, `transport: 'HTTPS_REDIRECT_LAB'`, the two fixed configured endpoints, `begin`, `complete`, `discard` and `isVerifiedPrincipal`.

- `begin({ browserSessionId })` returns only `{ ok: true, authorizationUrl }` after checking the fixed normalized HTTPS `.invalid` authorization and callback endpoints, single-valued parameter allowlist, code/query response, `openid email` scope, S256 challenge, state and nonce. The random binding is supplied by trusted server code, never selected through a query parameter.
- `complete({ browserSessionId, callbackUrl })` consumes that flow before validation or token exchange, requires the exact callback and locally bound state, and returns only the same foundation's verified opaque principal. The existing maintained OIDC-library foundation remains responsible for issuer, PKCE, nonce, signature, audience and token expiry.
- `discard({ browserSessionId })` invalidates this coordinator's pending capability without invoking a fabricated callback or token request. Underlying foundation transactions remain bounded and expire or are replaced.
- Late work cannot succeed after discard, replacement, expiration or clock rollback. Duplicate callbacks cannot cancel another request that already owns completion. Maximum pending capacity is 128 records with a five-minute lifetime. There is no automatic exchange retry or promise-racing side-effect timeout.

Failures contain only `authentication_failed`; upstream errors, claims and callback credentials are not exposed. Foundation methods are captured during construction. No browser-supplied principal can become authority through serialization.

## Browser-layer responsibilities

The coordinator alone is not a browser login implementation. Its caller must supply a dedicated TLS-only browser profile with a short-lived `Secure; HttpOnly; SameSite=Lax` transaction cookie, CSRF-protected login start, exact callback-only top-level navigation exception, and session rotation to a separate `Secure; HttpOnly; SameSite=Strict` authenticated cookie. Use fixed clean redirects after callback; never render or log callback query credentials. Keep synthetic JSON callback injection unavailable in that profile.

Cookies are host-bound, not port-bound. An invented app and issuer must use distinct logical hostnames with test-scoped loopback routing and certificate verification. Do not change the user's trust store, hosts file or browser profile. A protocol test client is not evidence of an actual browser-engine test.

## Verification

70 tests pass independently on Node 24.21.0 and 26.8.2. The same coverage is repeated, not 140 unique checks. Tests use newly generated invented keys and in-memory protocol fixtures; global `fetch` is disabled in this test file. RS256 and ES256 happy paths exercise the actual maintained OIDC client and JWS verification against the existing synthetic harness. Other tests cover configuration, redirect and callback tampering, issuer and browser-binding rejection, replay/concurrency, untrusted principal objects, bounded capacity, cancellation and clocks.

```sh
node --test deploy/fncp/identity-foundation/https-redirect-driver.test.mjs
```

These tests do not run a browser, perform TLS handshakes, activate a provider conversation, open existing stores, send invitations or establish production readiness. Transport and browser proof require separate composition and evidence.

## Primary protocol guidance

- [OAuth Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html): exact redirects, browser-bound CSRF protections, authorization code with PKCE and HTTPS transport.
- [Authorization Server Issuer Identification, RFC 9207](https://www.rfc-editor.org/rfc/rfc9207.html): validate the configured response issuer to prevent mix-up.
- [Set-Cookie reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie): Secure, HttpOnly, SameSite and `__Host-` cookie semantics.
