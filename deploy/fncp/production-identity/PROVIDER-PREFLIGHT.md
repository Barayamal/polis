# Offline public OIDC provider preflight

This is an offline planning check for the **existing `OIDC_PARTICIPANT_V1` adapter**, not a login test, provider approval, discovery client, deployment instruction or GO decision. It makes no network requests, creates no stores and writes no files. Every report remains `HOLD`, with `providerRuntimeVerified`, `deploymentAuthorized` and `participantAccessGranted` all `false`.

## Inputs and use

Use Node 22 or later; this command needs no npm installation. Supply two previously reviewed **public JSON files** with absolute, canonical, non-symlink paths:

```sh
node deploy/fncp/production-identity/provider-preflight.mjs \
  --metadata /absolute/reviewed/public-provider-metadata.json \
  --requirements /absolute/reviewed/public-adapter-requirements.json
```

The first input is the provider's public OIDC discovery metadata. The command does not retrieve it or authenticate its source. Preserve its source and collection date separately; no selected live provider has been validated by this addition. Do not put credentials, actual tokens, user claims, private keys, full service manifests or private file references into either input. The key-name guard catches common accidental private fields; it is not a general secret scanner.

The second input is exactly the eight public fields used by `createProductionIdentity`, also present in `production-service/service.mjs`'s identity schema. Omit its secret/CA file fields. The following values are **invented examples**, not configured services:

```json
{
  "issuer": "https://identity.example.invalid/",
  "authorizationEndpoint": "https://identity.example.invalid/authorize",
  "tokenEndpoint": "https://identity.example.invalid/token",
  "jwksUri": "https://identity.example.invalid/jwks",
  "callbackUri": "https://participant.example.invalid/oidc/callback",
  "clientId": "public-example-client",
  "tokenEndpointAuthMethod": "client_secret_basic",
  "signingAlgorithm": "RS256"
}
```

The current adapter accepts `client_secret_basic` or `client_secret_post`, and `RS256` or `ES256`. It demands exact canonical HTTPS strings without credentials, queries or fragments, and distinct authorization/token/JWKS/callback endpoints. These restrictions are narrower than OIDC in general. Cross-host public endpoints are allowed when their exact strings match. The service separately requires its callback to equal the participant origin plus `/oidc/callback`; provider metadata cannot establish that service-origin binding or registered callback.

The CLI prints only fixed check identifiers, result codes, counts and unverified runtime gates. It does not print input values, endpoint URLs, client IDs, paths or raw errors. There is no output-file option, stdin, URL fetch, automatic registration, environment configuration or overwrite operation. Do not redirect it onto an existing artifact. API exports are `evaluateProviderPreflight({metadata, requirements})`, `readPublicJson(path)` and `runProviderPreflightCli(args)`.

| Exit | `metadataAssessment` | Meaning |
| --- | --- | --- |
| 0 | `METADATA_MATCH` | All checked capabilities are explicitly advertised and match the public contract. **Runtime remains unverified; not deployment permission.** |
| 2 | `UNVERIFIED` | At least one needed assertion is absent or inconclusive; none explicitly conflict. |
| 1 | `INCOMPATIBLE` | At least one supplied endpoint/capability conflicts with this adapter. |
| 64 | `INPUT_REJECTED` | Invalid shape, type, file, private-field input, ambiguous JSON or limits. |

## What the comparison does—and does not—mean

Checks cover exact issuer/authorization/token/JWKS values; `code`, `query`, `authorization_code`, S256; the selected client-authentication method and ID-token signature algorithm; scope/claim advertisement; mandatory RFC 9207 `iss`; and conflicts with required PAR or signed request objects. Advertising optional PAR/JAR capability alone is harmless; requiring either conflicts with this adapter's plain authorization request.

Missing metadata is deliberately **not upgraded into explicit evidence**:

- Discovery defines omitted grant/authentication defaults; its query-mode default is qualified for Dynamic OpenID Providers. Codes distinguish these defaults from explicit claims. This checker does not apply them as a successful deployment check.
- Scope/claim lists can be incomplete: an omitted `email` or `email_verified` entry is `UNVERIFIED`, not definitive incompatibility. Malformed or empty lists are rejected.
- RFC 9207's omitted `iss`-support flag defaults false. This checker reports the omission as unverified and never assumes `iss` support; explicit false conflicts with this adapter.
- RFC 8414 does not infer PKCE support when its metadata field is absent. Missing S256 metadata remains unverified here; an explicit list without S256 is incompatible.
- Omitted PAR/JAR requirement flags default false, but remain unverified assertions here. Explicit requirement true is incompatible.

Defaults and optional field semantics: [OIDC Discovery §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata), [RFC 9207 §3](https://www.rfc-editor.org/rfc/rfc9207.html#section-3), [RFC 8414 §2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2), [RFC 9126 §5](https://www.rfc-editor.org/rfc/rfc9126.html#section-5), [RFC 9101 §10.5](https://www.rfc-editor.org/rfc/rfc9101.html#section-10.5). This is a bounded compatibility screen, not complete Discovery conformance certification; unrelated public extension metadata is ignored.

**The important email distinction:** the adapter reads `email` and boolean `email_verified: true` from the **ID token**. It does not call UserInfo or send a `claims` parameter. In code flow, `openid email` and a claims list do not ensure these values occur in the ID token. OIDC's scope-claims route normally uses UserInfo when an access token is issued, and requested claims may be withheld. A provider-specific configuration and actual controlled code-flow test must prove the adapter's stronger contract. [OIDC Core §5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims), [§5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse).

The remaining fixed gates require separate evidence of metadata provenance/freshness; the actual registered client and callback; HTTPS trust, endpoint behavior and key rotation; code/query/S256/state/nonce/iss; ID-token email placement; verified signature, exact audience/authorized party and time rules; real browser session/replay behavior; and deployment integration/owner approval. In particular, the adapter has zero clock tolerance, a ten-minute issuance-age limit and a one-hour maximum ID-token lifetime. Public metadata does not prove these behaviors, client-specific PAR/JAR policy, or the absence of extra callback parameters.

Verified-email authentication is **not** Indigenous heritage verification, adult status, WordPress approval, invitation authorization or voting eligibility. This tool cannot open a round, send invitations or create an activation.

## Input and test boundaries

Each file is limited to 65,536 bytes. The in-process wrapper is also limited to that serialized size. JSON is strict UTF-8 with duplicate names rejected, including escaped duplicate names. Data has a 16-level depth limit, 4,096-node limit, bounded arrays/strings and no executable/accessor/custom-prototype objects. CLI paths reject symlink ancestors, symlink files, hard links and non-regular files; file identity/size/timestamps are checked before and after a bounded read with `O_NOFOLLOW`. Use a trusted local directory: portable Node pathname checks are not an atomic defense against a malicious administrator racing ancestor-directory replacement. The API likewise does not sandbox hostile JavaScript Proxies. No source authenticity or cryptographic metadata validation is claimed.

Run only this new suite:

```sh
node --test deploy/fncp/production-identity/provider-preflight.test.mjs
```

Tests use invented metadata and temporary public JSON only, with deterministic cleanup. They cover explicit mismatches, defaults and uncertainty, ID-token email limitations, configuration restrictions, private-field/accessor rejection, malformed/oversized/ambiguous inputs, links/FIFOs, redacted output and read-only CLI behavior. They do not create a provider client, issue tokens, start services or access any participant records.

## Safe next steps

1. Review the eight public configuration values against the selected provider's reviewed metadata and current service origin. Do not insert secrets into the preflight inputs.
2. Run the offline command and resolve explicit incompatibilities. Obtain missing public documentation rather than interpreting an omission as proof. Re-run whenever endpoint or client policy changes.
3. Before any provider-account configuration, outbound request or real-provider test, obtain Dean's approval for that exact scope. Keep public surfaces closed.
4. Separately validate the real provider with invented test identities in the intended restricted deployment, covering every runtime gate. Record aggregate evidence, not tokens/claims or participant content.
5. Review service integration, recovery, operational controls and explicit deployment/activation authority independently. A preflight match cannot replace any of them.
