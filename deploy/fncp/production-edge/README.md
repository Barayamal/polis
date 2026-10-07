# Participant edge profiles

Status: local source and synthetic native-HTTPS compatibility proof. **Not
approved as public ingress.** The historical six-volume/eight-image package and
loopback API remain compatible. The explicit container profile adds a fixed
listener and service-name upstream, file custody, image recipe and opt-in V2
Compose/activation/ownership/archive contracts. Build, scan and full-stack runtime
evidence must be recorded separately for the exact release. Neither profile has
HTTP fallback, caller-controlled request transport, automatic retry or redirect
following.

## Why this seam exists

The existing participant BFF deliberately rejects unknown cookies and proxy
authority headers. A separate public edge may add `__cf_bm`, `Forwarded` or
`X-Forwarded-*`, even though those values are not participant credentials.
Blindly forwarding them would make legitimate requests fail. Relaxing the BFF
would enlarge its security boundary.

`edge.mjs` provides a narrow, independently testable adapter without changing
the BFF, identity, approval, activation, invitation, voting, or recovery code.
It does not verify eligibility. The existing process remains self-attestation,
staff approval, bound invitation and authenticated participant session.

## Security boundary

- `publicOrigin` is an exact canonical HTTPS origin. Incoming `Host` must match
  it; forwarding headers can never replace it. The TLS leaf must cover that
  hostname, match the private key, be current, and have `CA:false`. If extended
  key usage is present it must explicitly permit TLS server authentication;
  a client-authentication-only leaf is rejected before listener creation.
- Both legs use native verified TLS, minimum TLS 1.2. Upstream address/port are
  fixed at construction, and its certificate is verified against the configured
  CA and **public hostname**, not any request field. A TLS failure yields a
  generic 502, with no downgrade, retry, alternative origin or redirect follow.
- Cookie removal is explicit: `discardCookies: []` removes none;
  `discardCookies: ['__cf_bm']` removes only the reviewed edge-cookie name.
  `cf_clearance` and all other unreviewed names are denied, not silently stripped.
  Duplicate/malformed cookies are denied, including duplicates of a discarded
  cookie. The two `__Host-fncp-*` values reach the BFF unchanged for validation.
- Only a fixed list of non-authoritative proxy metadata is dropped: `Forwarded`,
  `X-Forwarded-For/Host/Proto/Port`, `X-Real-IP`, `CF-Connecting-IP`, `CF-IPCountry`,
  `CF-Ray`, `CF-Visitor`, and `CDN-Loop`. Their presence, absence and values do not
  establish CDN provenance, a trusted IP, authentication, or eligibility. A
  client can spoof these headers and gains no authority by doing so.
- `Authorization`, `Proxy-Authorization`, `X-FNCP-*` and unreviewed
  `X-Forwarded-*` are rejected. Duplicate HTTP headers and `Connection` values
  that nominate other headers are rejected before sanitization. Hop-by-hop
  fields are not forwarded.
- `Origin`, `Sec-Fetch-*`, CSRF tokens and application cookies are not created,
  replaced or repaired. Their existing strict BFF checks still apply. The edge
  neither accepts Cloudflare Access as participant identity nor adds an identity
  bridge.
- The route/method allowlist exposes only the participant page/assets and BFF
  session, OIDC, registration, invitation redemption and participation routes.
  It does **not** expose native Pol.is `/api/*`, WordPress, the event receiver,
  operator socket, results, health endpoints, CONNECT or WebSocket tunnels.
- Request bodies are bounded at 4 KiB, responses at 1 MiB, headers at 16 KiB,
  and operations have short deadlines. No request values, tokens, cookies,
  callback queries or private error details are logged by this module.
- Redirects, `Set-Cookie` attributes (including separate header values), CSP,
  HSTS and no-store controls are preserved. No backend cookie domain or redirect
  rewriting is performed.

## Local proof

Run from the source checkout using its installed dependencies:

```sh
node --test --test-reporter=spec deploy/fncp/production-edge/edge.test.mjs
```

On 22 September 2026, Node v26.8.2: **13/13 tests passed**, with no failures,
skips or cancellations. The suite creates fresh ephemeral certificates and
invented users. It does not contact public services or trust an external CA.
All owned listeners are closed and temporary test material is removed.

The integrated test uses the **unchanged real production BFF** with native
HTTPS synthetic identity/provider/WordPress peers. It proves login, OIDC
callback/303 redirect, pending registration and logout through the edge. It
also proves rejection of bad CSRF, cross-origin/cross-site private operations,
malformed application cookies, and voting while admission remains closed.
Separate tests exercise spoofed metadata, wrong Host, unknown/duplicate cookies,
private-route denial, certificate trust/hostname failures and listener closure.

This is HTTP-protocol compatibility proof, **not** browser-trusted live ingress
proof. Test clients intentionally connect to a loopback test port while retaining
the configured public Host/Origin, representing a future separately reviewed
network mapping. It does not prove live public port 443 routing, browser
same-origin/SameSite/secure-cookie behaviour across a real CDN and identity
provider, CDN network policy, or image/Compose integration. No approval or
activation gate is satisfied merely by passing these tests.

## Before any production use

1. Independently review this adapter and decide the actual ingress topology.
   Keep the participant application, receiver, WordPress and native Pol.is
   private. Do not expose a port by copying this test configuration.
2. Bind the chosen edge artifact/configuration into image digests, deployment
   activation, the validated Compose/network model and joined backup/recovery
   evidence. This new component is not covered by the frozen image lock.
3. Establish and test authenticated ingress provenance/network restrictions
   separately if relying on a CDN/tunnel. Forwarding headers are not proof of
   provenance. Rate limits, bot policy and client IP handling belong to that
   explicitly reviewed layer, not this sanitizer.
4. Use approved hostname certificates and a documented renewal/rollback path.
   Review separate staff/admin ingress and MFA; none is supplied here.
5. Run real-browser staging negative tests with the actual provider and CDN,
   including login redirects, forwarded-link denial, warm-session revocation,
   closure, no-cache behaviour and unknown-cookie handling. Use invented users
   and a closed round; do not reuse registration responses.
6. Obtain Dean's explicit deployment approval before live DNS, services,
   certificates/accounts requiring external action, publication or spending.
   Launch/admission remains a separate approved, deployment-bound action.

Pol.is's [official source and self-hosting overview](https://github.com/compdemocracy/polis/blob/stable/README.md)
and [HTTPS guidance](https://github.com/compdemocracy/polis/blob/stable/docs/ssl.md)
remain upstream references. This Barayamal-specific participant-security seam is
custom work, not a claim that upstream Pol.is supplies these access guarantees.


## Container profile and image

`createContainerParticipantEdge({configurationPath})` in `material.mjs` reads
exactly four owned private files from a canonical0700 directory. The normal
`main.mjs` only accepts `/run/fncp/edge/config.json` and verifies custody each
second, closing the listener if material changes. See the exact V2 material
shape and topology in [COMPOSE.md](../production-deployment/COMPOSE.md).

`Dockerfile` builds an independent ninth runtime image from the pinned Node22
base and patched BusyBox recipe used by the participant image. It copies only
the edge, custody and canonical-contract modules: no installer, operator or
offline activation signer. Build from repository root with an explicit reviewed
`SOURCE_REVISION`; resolve and scan its immutable image ID before making the
V2 lock. `Dockerfile.dockerignore` narrows the build context.

The container transport permits only `0.0.0.0:8443` listening and fixed upstream
`participant-edge-upstream:8443`. Native TLS verifies the upstream CA and public
hostname; DNS chooses the address for that fixed Compose alias, never from a
request. `createParticipantEdge` remains loopback-only for synthetic tests. The
shared sanitizer continues to exclude WordPress, receiver, operator and native
Pol.is routes. The closed V2 composition publishes no host port. A public staging
route remains a separately approved deployment change.

Run the compatibility and material suites with:

```sh
node --test deploy/fncp/production-edge/edge.test.mjs deploy/fncp/production-edge/material.test.mjs
```

Source/material tests cover the fixed transport, missing/unexpected material,
symlink/hardlink and ownership/mode rejection, certificate identity/purpose, and
post-construction mutation refusal. They do not by themselves prove container
DNS routing, browser behavior or a rebuilt/scanned image.
