# Local strict-service lifecycle ownership

Classification: **KEEP_CLOSED / LOCAL_SYNTHETIC_ONLY**. This component coordinates already-constructed local services. It is neither a hosted release nor participant, eligibility, identity-provider, or activation authority.

## API

```js
const supervisor = createServiceSupervisor({
  services: [
    { name: 'access', service: access, port: 8099 },
    { name: 'receiver', service: receiver, port: 8101 },
    { name: 'browser', service: browser, port: 8100 },
  ],
  closeAuthority() { admissionGuard.close(); },
});

const { origins } = await supervisor.start(); // Keep in the private caller.
const aggregate = supervisor.snapshot();     // Names and lifecycle states only.
await supervisor.close();
```

The module does not construct these services, consume environment variables, bind a socket itself, expose an operator route, open Pol.is, grant authority, or persist state. Its caller remains responsible for construction rollback before ownership can be transferred.

## Contract and ordering

- Validate the complete exact configuration before invoking any lifecycle method. There must be 1–8 distinct service objects and safe unique lowercase names, each with captured own callable `listen` and `close` data properties. Reject accessors, unknown fields, sparse/extended service arrays, duplicate nonzero ports and non-integer/out-of-range ports. Port 0 is permitted only as an ephemeral assignment request, not as an advertised origin.
- `start()` is single-attempt and listens sequentially in supplied order. By default, every result must be a distinct canonical `http://127.0.0.1:<1–65535>` origin matching the requested port unless it was 0. The only opt-in exception is an entry's exact `expectedOrigin: 'https://browser.example.invalid:<port>'` with a matching explicit nonzero, non-443 port. It must be canonical, contain no path/query/fragment/userinfo, and match the adapter result exactly. The fixed `.invalid` name is an isolated lab origin, not permission to listen on a remote address. No HTTP fallback or arbitrary host is accepted. Return a frozen private origins map only after every service starts and closure has not begun. No origin is included in `snapshot()` or propagated in an error.
- A startup failure closes **all constructed/owned services**, including those not yet started, and remains terminal. A duplicate start or start after closure is refused.
- `close()` publishes its closing latch and stable promise before callbacks, immediately invokes `closeAuthority` exactly once, then invokes all service closes in reverse order. It does not wait for an earlier drain before invoking the next close: one service may need another's cancellation to finish. Every result is awaited before successful closure is reported.
- A close error does not suppress another service's close. Errors are fixed messages/codes without original causes, stack excerpts, endpoint addresses or third-party messages. A failed close is not retried.
- Closure cancels pending startup observation, even if a listener ignores cancellation. Every actual service is nevertheless instructed to close and its drain is awaited. Listener rejection handlers stay attached, so a later rejection cannot become an unhandled startup error.
- No timer, forced termination, side-effect retry, restart, provider allowlist removal or round-state mutation is implemented. A genuinely non-settling service or authority drain remains pending; it must not be reported as safely completed.

The supervisor does not create a dependency from closure back to startup. Adapters must likewise not await the supervisor's start/close promise from inside their own `close()` or `closeAuthority()` implementations. Direct returned self-waits are rejected; arbitrary indirect asynchronous self-dependency is outside the adapter contract and cannot be made safely complete with a timeout.

Lifecycle snapshots are immutable copies containing only an overall `state` and bounded `{ name, state }` service entries. The running state is exactly `RUNNING`; other aggregate states are `CREATED`, `STARTING`, `CLOSING`, `CLOSED` and `FAILED`. A successfully drained startup failure remains `FAILED`, not a restartable state.

## Evidence

`supervisor.test.mjs` has **92 tests**: the original 72 plus 20 explicit HTTPS expectation checks, passing independently on Node **24.21.0** and **26.8.2** on 13 September 2026. These tests use only deterministic fake/deferred adapters: no actual listener, provider, Docker/VM, original store, archive, configuration, key, participant or public site is accessed.

```sh
node --test deploy/fncp/strict-service/supervisor.test.mjs
```

Coverage includes startup/closure races, terminal rollback, real drain ordering, close failures, re-entrancy, duplicate calls, captured configuration, default HTTP/explicit HTTPS origin validation, immutable aggregate snapshots and fail-closed configuration validation. Integration with genuine first-party services requires separate composition tests; these 92 checks do not prove production deployability.
