# Actual loopback TLS under synthetic OIDC interception

This is test support, **not a real identity provider, browser redirect, production
transport or approval to launch**. The existing identity foundation and synthetic
browser-driver contracts remain `SYNTHETIC_ONLY` / `SYNTHETIC_INTERCEPT`.

## What the test adds

The unchanged in-memory synthetic issuer produces invented one-use authorization
codes and genuinely signed ID tokens. A separate HTTPS server delivers its token
and JWKS responses over actual TLS. A new identity-foundation instance intercepts
only the two exact logical URLs at `https://identity.example.invalid/` and sends
their bytes exclusively to an ephemeral listener bound to `127.0.0.1`.

Each request uses an explicit freshly generated test certificate as its trust
anchor, the fixed invented hostname for SNI, Node's default hostname verification,
`rejectUnauthorized: true`, no pooled/global agent and a literal loopback socket
destination. No DNS resolution, proxy, remote-provider discovery, redirect follow,
system/browser trust installation or environment override is used. The test helper
cannot be configured with another host, endpoint, port, private key or CA.

OpenSSL generates a new EC private key and short-lived self-signed certificate in
an invocation-owned, mode-0700 temporary directory. The two files are read only by
the helper and removed immediately; no key material is printed or retained in the
repository. This tests explicit local trust, **not a publicly trusted certificate
chain, public certificate issuance or certificate renewal**.

The adapter has a bounded whole-response deadline, propagates caller cancellation,
limits request and response bodies to 64 KiB, makes no automatic retries, and never
follows redirects. Its response still goes through the existing maintained OIDC
library and signature/issuer/audience/state/nonce/PKCE checks. HTTP request counts
and TLS authorization results are aggregate-only. Shutdown destroys only its own
sockets and independently checks connection refusal on its former port.

## Run

From the repository root, with installed locked identity dependencies, Node 24+
and OpenSSL 3 available:

```sh
node --test deploy/fncp/identity-foundation/synthetic-tls-lab.test.mjs
```

The suite covers trusted token/JWKS exchange, wrong trust anchor, certificate SAN
mismatch, token and JWKS redirects, stalled headers/bodies, oversized/non-JSON/
truncated responses, caller abort, no external routing, PKCE code substitution,
one-use and concurrent callbacks, the unchanged synthetic browser driver, and
verified cleanup. It opens only short-lived loopback test listeners; no Docker,
Pol.is service, WordPress service, browser, email or participant record is used.

## Remaining boundaries

The authorization response is still explicitly injected by the private test
driver. No browser follows an authorization redirect; the local browser BFF still
uses its existing same-origin CSRF JSON callback simulation. Consequently this
does **not** prove cross-site callback cookies, an approved real issuer/client,
operator MFA, provider logout/revocation, genuine mailbox control or Indigenous
heritage verification. No synthetic identity is registered, invited or activated
by this test. Production remains closed.

## Primary references

- [Node HTTPS request options](https://nodejs.org/api/https.html#httpsrequestoptions-callback).
- [Node TLS hostname verification](https://nodejs.org/api/tls.html#tlscheckserveridentityhostname-cert).
- [OpenSSL certificate request/self-signed certificate generation](https://docs.openssl.org/3.6/man1/openssl-req/).
- [Pol.is official self-hosting/source guidance](https://github.com/compdemocracy/polis/blob/stable/README.md).

This lab closes a local TLS-transport evidence gap in the separate FNCP identity
adapter. It does not claim Pol.is supplies the eligibility workflow or this adapter.
