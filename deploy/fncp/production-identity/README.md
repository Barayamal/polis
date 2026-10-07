# Separate participant OIDC adapter

This package implements participant **authentication** over verified HTTPS. It does not implement the production BFF, WordPress registration, approval, invitations, activation, participant access, staff authentication, deployment or recovery. No real identity provider or account has been used to validate it. The selected provider must still pass the contract tests in the deployment environment.

The older `identity-foundation`, `local-access`, `strict-service`, `activation-foundation` and `wordpress-identity` entry points retain their synthetic-only guards. This adapter has the distinct `OIDC_PARTICIPANT_V1` profile; it cannot be supplied to those synthetic compositions.

## Constructor contract

`createProductionIdentity(options)` in `identity.mjs` accepts exactly these fields:

| Field | Contract | Custody |
| --- | --- | --- |
| `issuer` | Exact canonical HTTPS issuer string, including any trailing slash. | Public configuration; changing it changes account mapping. |
| `authorizationEndpoint` | Explicit canonical HTTPS code-flow endpoint. | Public configuration. |
| `tokenEndpoint` | Explicit canonical HTTPS token endpoint; only POST is allowed. | Public configuration. |
| `jwksUri` | Explicit canonical HTTPS signing-key endpoint; only GET is allowed. | Public configuration. |
| `callbackUri` | Exact canonical HTTPS callback; query response mode. | Public configuration; must match provider registration and BFF routing. |
| `clientId` | Nonempty client ID, at most 256 characters. | Public configuration. |
| `clientSecret` | Required confidential-client secret, at most 2048 characters, no control characters. | Private secret reference resolved in process. |
| `tokenEndpointAuthMethod` | Exactly `client_secret_basic` or `client_secret_post`. | Public configuration, selected against provider metadata. |
| `signingAlgorithm` | Exactly `RS256` or `ES256`. | Public configuration. |
| `identityKey` | `Uint8Array`, 32–64 bytes; copied by the adapter. | Stable private mapping key, separate from all other key roles. |
| `ca` | Optional PEM certificate bundle as `Uint8Array`, at most 65,536 bytes. | Public trust material, loaded from a reviewed file. If omitted, Node's default trust store is used. |
| `relay` | Optional exact `OIDC_FIXED_RELAY_V1` descriptor: host `oidc-relay`, token port 8445, JWKS port 8446, and 64-hex `policySha256`. | Trusted composition only; binds a separately reviewed fixed relay policy. Current file-backed service/Compose installer do not accept this field yet. |
| `now` | Optional trusted in-process clock function, defaults to `Date.now`. | Composition dependency, never request input. |

URLs cannot contain credentials, query strings, fragments or aliases that canonicalize to another value. Discovery, arbitrary `fetch`, agents, resolvers, HTTP, redirects, arbitrary proxy selection and certificate-verification overrides are not configuration options. The token, authorization, JWKS and callback endpoints must be distinct. Operator-selected endpoints are trusted configuration; no provider compatibility is inferred from the URL shape.

The profile requires authorization response `iss` (RFC 9207), code flow with PKCE S256/state/nonce, a cryptographically verified ID token, the exact client audience, no additional audiences, an exact authorized party when present, a nonempty subject, `email_verified: true` and a nonempty email claim. It requests only `openid email`. Access-token audience and staff/email-claim behavior are separate contracts; this package does not establish them. ID tokens must be issued within the preceding ten minutes, cannot exceed a one-hour lifetime, and use zero clock tolerance. A provider that does not satisfy this profile is unsupported until its contract is reviewed and tested.

## Private API and ownership

The owning BFF creates one adapter and retains it for the process lifetime. It creates its own random server-held browser session bindings, supplies them only from that session store, and never lets a request select the issuer, verifier, account, round or mapping function.

| Method | Result and obligation |
| --- | --- |
| `begin({browserSessionId})` | `{ok:true,authorizationUrl}` or generic failure. Binding is 43–256 base64url characters; the BFF must generate at least 32 random bytes. Pending capacity is 128; a binding's newer login replaces its older transaction. |
| `complete({browserSessionId,callbackUrl})` | `{ok:true,principal}` or `{ok:false,error:'authentication_failed'}`. Callback transaction is consumed before the grant. The frozen principal stays in process. |
| `discard({browserSessionId})` | Drops a pending login without exposing whether it existed. The BFF calls this when disposing or replacing a browser session. |
| `isVerifiedPrincipal(principal)` | Requires the exact live object issued by this instance. A copied, serialized, fake or other-instance principal fails. |
| `principalDeadline(principal)` | Private expiry milliseconds or `null`. Maximum fifteen minutes, capped at ID-token expiry. |
| `participantXid(principal,conversationId)` | Private round-specific pseudonym. It is not an approval or provider allowlist entry. |
| `publicResult(result)` | Authentication/verified-email booleans and explicit `participantAccessGranted:false`; no account, XID, raw claims or tokens. |
| `close()` | Permanently closes the adapter, cancels HTTPS work, invalidates principals and pending logins and zeroes its copied mapping-key buffer. It does not claim to securely erase every JavaScript string or external caller-owned key copy. |

The adapter never exposes or logs provider error descriptions, subject, email, ID/access/refresh tokens, client secrets or callback contents. Account identity is HMAC of a versioned encoding of **issuer + subject**. Email never links accounts. A round XID is derived separately from the opaque account and conversation. The mapping key must not be generated anew on every restart. Restore must retain the correct key/version and issuer configuration, while discarding old process capabilities and browser sessions.

Any observed backward or invalid clock value permanently closes this adapter, including an exception from the clock. Correcting the clock does not revive old principals. The future service composition must also close activation/participation on clock failure and surface a safe operational signal; authentication failure alone is not a complete service incident workflow.

## Native transport limits

The transport uses Node HTTPS with explicit `rejectUnauthorized:true`, default hostname verification, TLS 1.2 minimum and no pooled agent. `NODE_TLS_REJECT_UNAUTHORIZED=0` cannot override this explicit setting. A CA bundle replaces the default trust set only for this adapter. Token requests can send client authentication only to the fixed token endpoint; JWKS requests cannot contain authorization. Cookies, caller Host headers and other ambient headers are rejected. No Set-Cookie or provider-specific headers are passed back to the OAuth library.

The optional fixed relay routes only the socket destination. HTTPS retains the original provider SNI, Host and certificate-name check; the relay sees encrypted traffic. Relay failure has no direct fallback. This is source-level integration with the [relay foundation](../production-egress/README.md), not installed Compose/network assurance. The route's policy hash is validated here for shape; actual staged relay bytes and host enforcement must be matched during deployment integration. The named loopback-only transport fixture is rejected by the production identity constructor and cannot route nonloopback provider endpoints.

At most 32 endpoint requests are admitted concurrently. A five-second deadline covers connection, headers and the complete response body. Requests are bounded to 16 KiB; JSON responses to 64 KiB. Redirects, compressed bodies, non-JSON content, truncation and oversized responses fail generically. DNS and trust are the configured host's responsibility; the adapter provides no dynamic service discovery or failover.

## Verification

From this directory, with Node 22 or later and OpenSSL available:

```sh
npm ci --ignore-scripts --no-audit --no-fund
npm test
```

The lock pins `openid-client` 6.8.8 and its dependency tree; `jose` is used by the fixture to sign actual test tokens. Tests create temporary HTTPS issuers on random loopback ports and fresh certificates/keys, then close their sockets and verify listener refusal. They do not contact an external provider, change the system trust store, start Docker/VM services, use retained keys, or create real accounts. The deliberate environment-override test produces Node's warning about `NODE_TLS_REJECT_UNAUTHORIZED`; it verifies that this adapter still rejects the bad CA.

The fixture's local HTTPS success proves this adapter's protocol and transport boundary. It does not prove a selected external provider, browser cookies/redirects, staff login, production service startup, Compose integration or pilot readiness.
