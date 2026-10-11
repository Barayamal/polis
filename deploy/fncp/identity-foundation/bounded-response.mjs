import { performance } from 'node:perf_hooks';

const failure = () => new Error('Identity transport failed.');

// Cancellation is best effort: an injected transport/stream may ignore it or
// never settle it. Never make authentication failure wait for that cooperation.
function cancel(target) {
  try { Promise.resolve(target?.cancel()).catch(() => {}); } catch { /* no details */ }
}

/** Internal transport primitive; not an identity configuration option.
 * One deadline covers transport headers AND the complete bounded body. Smaller
 * budgets are useful for isolated tests; callers cannot raise the fixed ceiling.
 * This cannot interrupt synchronous JS or forcibly stop a noncooperative adapter.
 */
export async function boundedJsonResponse(transport, input, init, {
  timeoutMs = 5000, maxBytes = 65_536,
} = {}) {
  if (typeof transport !== 'function' || !Number.isSafeInteger(timeoutMs)
    || timeoutMs < 1 || timeoutMs > 5000 || !Number.isSafeInteger(maxBytes)
    || maxBytes < 1 || maxBytes > 65_536) throw failure();
  const controller = new AbortController();
  const parent = init?.signal;
  const expires = performance.now() + timeoutMs;
  const abort = () => controller.abort();
  const timer = setTimeout(abort, timeoutMs);
  let response;
  let reader;
  const check = () => {
    if (performance.now() >= expires) abort();
    if (controller.signal.aborted) throw failure();
  };
  // Remove each abort listener as its individual wait settles. A single shared
  // Promise.race loser per chunk would retain an ever-growing list of reactions.
  const wait = (promise) => new Promise((resolve, reject) => {
    const stopped = () => reject(failure());
    controller.signal.addEventListener('abort', stopped, { once: true });
    Promise.resolve(promise).then(resolve, reject).finally(() => {
      controller.signal.removeEventListener('abort', stopped);
    });
    if (controller.signal.aborted) stopped();
  });
  try {
    if (parent) {
      parent.addEventListener('abort', abort, { once: true });
      if (parent.aborted) abort();
    }
    check();
    response = await wait(Promise.resolve().then(() => {
      check();
      return transport(input, { ...init, signal: controller.signal,
        redirect: 'error', credentials: 'omit' });
    }).then((value) => {
      // A late response never re-enters authentication after its deadline.
      if (controller.signal.aborted || performance.now() >= expires) {
        cancel(value?.body);
        throw failure();
      }
      return value;
    }));
    check();
    if (!(response instanceof Response) || response.redirected
      || (response.url && response.url !== String(input))
      || (response.status >= 300 && response.status < 400)
      || !/^application\/(?:[a-z0-9.+-]+\+)?json(?:\s*;|$)/iu.test(response.headers.get('content-type') ?? ''))
      throw failure();
    reader = response.body?.getReader();
    if (!reader) throw failure();
    const chunks = [];
    let bytes = 0;
    while (true) {
      check();
      const { done, value } = await wait(reader.read());
      check();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw failure();
      if (value.byteLength === 0) continue; // Do not accumulate unbounded empty-chunk metadata.
      bytes += value.byteLength;
      if (bytes > maxBytes) throw failure();
      // Own a copy: stream producers can otherwise mutate an earlier chunk.
      chunks.push(Buffer.from(value));
    }
    return new Response(Buffer.concat(chunks), { status: response.status, headers: response.headers });
  } catch {
    abort();
    cancel(reader ?? response?.body);
    throw failure();
  } finally {
    clearTimeout(timer);
    parent?.removeEventListener('abort', abort);
    // A pending read may make releaseLock throw; it must not delay failure.
    try { reader?.releaseLock(); } catch { /* best effort */ }
  }
}
