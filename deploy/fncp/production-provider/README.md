# Private Pol.is production transport

`createProductionPolisProvider()` implements the private HTTPS wire contract for this fork. It grants no approval, activation or participant session and is not a listener, launcher or deployment. Existing local/synthetic guards are unchanged.

The constructor accepts exactly `{origin, conversationId, statementIds, gatewaySecret, providerSecret, ca?}`. `origin` must equal its canonical HTTPS origin, with no path, query, fragment, credentials or default-port alias. Fifteen distinct nonnegative integer statement IDs are copied and sorted. Gateway and allowlist credentials must be distinct 32–512 character base64url strings; neither is exposed. Optional CA bytes are copied, bounded to 64KiB and parsed as PEM CA certificates. Without `ca`, Node's verified default trust store applies.

The frozen result is registered in a private WeakSet. `isProductionPolisProvider()` rejects copied or forged objects. Its API is:

- `binding()` returns a new public copy of `{origin, conversationId, statementIds, trustSha256}`. The trust digest hashes exact configured CA bytes, or the literal default-trust profile marker. The marker is not a digest of every runtime trust root; runtime image/configuration custody remains necessary. Activation binds the SHA256 of this object's canonical encoding.
- `allowlist('upsert'|'readback'|'remove', xid)` calls the exact three POST `/fncp/private/xid-allowlist/*` paths. Upsert carries operationVersion 1, removal 2, with stable `allow-`/`remove-` idempotency keys derived from conversation+XID. Writes require 204. Readback requires 200 and an exact matching conversation/XID/version/presence object. Version 2 removal is terminal; this adapter never resets it.
- `participate('init'|'next'|'vote', xid, values={})` uses only GET `/api/v3/participationInit`, GET `/api/v3/nextComment`, and POST `/api/v3/votes`. Only a configured `tid` and vote−1/0/1 are accepted for a vote; other calls accept no values. Init returns `{nextComment,votes:[{tid,vote}]}`; next returns a statement or `{}`; vote returns `{nextComment}`. Statements expose only `{tid,txt,remaining?,total?}`. Text/counts/IDs are bounded, and any returned total must be 15. Native auth, user, participant, currentPid, PCA, famous, arbitrary nested data and headers never escape.
- `close()` irreversibly rejects new work and aborts admitted HTTPS work. It clears internal credential references but does not claim to erase every JavaScript string or caller-owned copy.

The native Node HTTPS transport sets certificate and hostname verification explicitly, TLS 1.2 minimum, no pooled/custom agent, no redirect following, and no caller-supplied fetch/resolver/proxy/header options. It sends no Cookie, Origin, forwarded-protocol header or ambient browser credentials. A trusted TLS terminator must set its own forwarded protocol for an HTTP backend. The private allowlist bearer never accompanies participant requests; the gateway key never accompanies allowlist requests. TLS alone does not prove that the origin is network-private: deployment must restrict it.

At most 32 operations are admitted. A five-second monotonic deadline covers connection, headers and complete body. Requests are limited to 16KiB, response headers to 16KiB and response bodies to 256KiB. Redirects, compressed, truncated, non-JSON and oversized bodies fail generically. There is no retry. A failed/in-flight vote can already have reached the provider; errors carry `outcome:'unconfirmed'`. The owning access service must recheck live principal, activation generation, current approval, round state and provider binding before and after awaited effects, withholding uncertain results without claiming rollback.

The constructor binds IDs, not approved text. The owning composition verifies every returned text against its reviewed 15-statement seed registry and binds that registry's digest into activation. Native Pol.is votes additionally require `conversations.is_active=true`; the closed core's startup check requires false. This adapter does not invent a conversation-open route. A separate reviewed operator transition must open/close the native round and preserve restart-closed behavior before real voting can be claimed.

Tests use fresh temporary certificates and actual loopback HTTPS, invented data and no external service. They cover correct routes/credentials, typed projection, wrong CA/hostname, the environment TLS-disable override, mutation/config rejection, malformed bodies, timeout, concurrency and irreversible close. They do not prove the selected private production origin, real identities, eligibility or deployment.

```sh
node --test deploy/fncp/production-provider/provider.test.mjs
```
