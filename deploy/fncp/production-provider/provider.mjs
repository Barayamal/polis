import { createHash, X509Certificate } from 'node:crypto';
import { request } from 'node:https';
import { performance } from 'node:perf_hooks';
import { checkServerIdentity } from 'node:tls';

export const PROFILE = 'POLIS_PRIVATE_PROVIDER_V1';
const adapters = new WeakSet();
export const isProductionPolisProvider = value => adapters.has(value);
const sha = value => createHash('sha256').update(value).digest('hex');
const plain = value => value !== null && typeof value === 'object' && !Array.isArray(value)
  && [Object.prototype, null].includes(Object.getPrototypeOf(value));
const exact = (value, required, optional = []) => plain(value)
  && Reflect.ownKeys(value).every(k => typeof k === 'string' && [...required, ...optional].includes(k))
  && required.every(k => Object.hasOwn(value, k))
  && Object.values(Object.getOwnPropertyDescriptors(value)).every(d => Object.hasOwn(d, 'value'));
const secret = value => typeof value === 'string' && /^[A-Za-z0-9_-]{32,512}$/u.test(value);
const xidValid = value => typeof value === 'string' && /^fncp_[A-Za-z0-9_-]{16,251}$/u.test(value);
const unavailable = () => Object.assign(new Error('Provider unavailable.'), { status: 503, outcome: 'unconfirmed' });
const invalid = () => Object.assign(new Error('Invalid provider operation.'), { status: 400, outcome: 'not_started' });
const finiteId = value => Number.isSafeInteger(value) && value >= 0 && value <= 2147483647;

/** Native private HTTPS transport. No generic request or secret fields escape. */
export function createProductionPolisProvider(options) {
  let origin, conversationId, statementIds, gatewaySecret, providerSecret, ca, trustSha256;
  try {
    if (!exact(options, ['origin', 'conversationId', 'statementIds', 'gatewaySecret', 'providerSecret'], ['ca'])) throw invalid();
    ({ origin, conversationId, gatewaySecret, providerSecret } = options);
    const url = new URL(origin);
    if (typeof origin !== 'string' || origin.length > 2048 || /[\u0000-\u0020\u007f]/u.test(origin)
      || url.protocol !== 'https:' || url.origin !== origin || url.username || url.password
      || !/^[0-9][A-Za-z0-9_-]{5,99}$/u.test(conversationId ?? '')
      || !secret(gatewaySecret) || !secret(providerSecret) || gatewaySecret === providerSecret
      || !Array.isArray(options.statementIds) || options.statementIds.length !== 15
      || !options.statementIds.every(finiteId) || new Set(options.statementIds).size !== 15) throw invalid();
    statementIds = Object.freeze([...options.statementIds].sort((a, b) => a - b));
    if (options.ca !== undefined) {
      if (!(options.ca instanceof Uint8Array) || options.ca.byteLength < 1 || options.ca.byteLength > 65536) throw invalid();
      ca = Buffer.from(options.ca);
      const pem = ca.toString('utf8');
      const pattern = /-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----/gu;
      const certs = pem.match(pattern);
      if (!certs?.length || pem.replace(pattern, '').trim() || certs.some(c => !new X509Certificate(c).ca)) throw invalid();
    }
    trustSha256 = sha(ca ?? Buffer.from('NODE_DEFAULT_VERIFIED_TRUST_V1'));
  } catch { throw invalid(); }
  const binding = Object.freeze({ origin, conversationId, statementIds, trustSha256 });
  const tids = new Set(statementIds), active = new Set();
  let closed = false;
  function perform(path, method, headers, body) {
    if (closed || active.size >= 32) return Promise.reject(unavailable());
    const raw = body === undefined ? undefined : JSON.stringify(body);
    if (raw !== undefined && Buffer.byteLength(raw) > 16384) return Promise.reject(invalid());
    return new Promise((resolve, reject) => {
      let req, response, settled = false;
      const deadline = performance.now() + 5000;
      const finish = (error, value) => {
        if (settled) return;
        settled = true; clearTimeout(timer); active.delete(abort);
        if (error) { response?.destroy(); req?.destroy(); reject(unavailable()); } else resolve(value);
      };
      const abort = () => finish(true);
      const timer = setTimeout(abort, 5000); active.add(abort);
      try {
        req = request(origin + path, { method, ca, rejectUnauthorized: true, checkServerIdentity,
          minVersion: 'TLSv1.2', agent: false, maxHeaderSize: 16384,
          headers: { ...headers, accept: 'application/json', connection: 'close',
            ...(raw === undefined ? {} : { 'content-type': 'application/json', 'content-length': Buffer.byteLength(raw) }) } }, res => {
          response = res;
          const status = res.statusCode, type = res.headers['content-type'];
          if (closed || req.socket.authorized !== true || performance.now() >= deadline
            || !Number.isInteger(status) || status < 200 || status >= 600 || status >= 300 && status < 400
            || res.headers['content-encoding'] !== undefined
            || status !== 204 && (typeof type !== 'string' || !/^application\/json(?:\s*;|$)/iu.test(type))) { abort(); return; }
          const chunks = []; let size = 0;
          res.on('data', chunk => {
            size += chunk.length;
            if (closed || size > 262144 || performance.now() >= deadline) { abort(); return; }
            chunks.push(Buffer.from(chunk));
          });
          res.on('aborted', abort); res.on('error', abort);
          res.on('end', () => {
            if (settled) return;
            try {
              if (closed || !res.complete || performance.now() >= deadline || status === 204 && size !== 0) throw unavailable();
              const body = status === 204 ? null : JSON.parse(Buffer.concat(chunks).toString('utf8'));
              finish(false, { status, body });
            } catch { abort(); }
          });
        });
        req.on('error', abort); if (raw !== undefined) req.write(raw); req.end();
      } catch { abort(); }
    });
  }
  function statement(value) {
    if (value === null) return null;
    if (!plain(value) || !finiteId(value.tid) || !tids.has(value.tid)
      || typeof value.txt !== 'string' || value.txt.length < 1 || value.txt.length > 10000 || value.txt.includes('\0')) throw unavailable();
    const result = { tid: value.tid, txt: value.txt };
    for (const key of ['remaining', 'total']) if (Object.hasOwn(value, key)) {
      if (!Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > 15) throw unavailable();
      result[key] = value[key];
    }
    if (result.total !== undefined && result.total !== 15 || result.remaining !== undefined && result.remaining < 1) throw unavailable();
    return Object.freeze(result);
  }
  const adapter = Object.freeze({
    profile: PROFILE,
    binding: () => structuredClone(binding),
    async allowlist(operation, xid) {
      if (!['upsert', 'remove', 'readback'].includes(operation) || !xidValid(xid)) throw invalid();
      const body = { conversationId, participantXid: xid }, headers = { authorization: `Bearer ${providerSecret}` };
      if (operation !== 'readback') {
        body.operationVersion = operation === 'upsert' ? 1 : 2;
        headers['idempotency-key'] = `${operation === 'upsert' ? 'allow' : 'remove'}-${sha(conversationId + ':' + xid)}`;
      }
      const result = await perform(`/fncp/private/xid-allowlist/${operation}`, 'POST', headers, body);
      if (result.status !== (operation === 'readback' ? 200 : 204)) throw unavailable();
      if (operation !== 'readback') return null;
      const value = result.body;
      if (!exact(value, ['conversationId', 'participantXid', 'operationVersion', 'present'])
        || value.conversationId !== conversationId || value.participantXid !== xid || typeof value.present !== 'boolean'
        || ![null, 1, 2].includes(value.operationVersion)
        || value.present !== (value.operationVersion === 1)) throw unavailable();
      return Object.freeze({ ...value });
    },
    async participate(kind, xid, values = {}) {
      if (!['init', 'next', 'vote'].includes(kind) || !xidValid(xid)
        || !exact(values, kind === 'vote' ? ['tid', 'vote'] : [])
        || kind === 'vote' && (!tids.has(values.tid) || ![-1, 0, 1].includes(values.vote))) throw invalid();
      const route = { init: '/api/v3/participationInit', next: '/api/v3/nextComment', vote: '/api/v3/votes' }[kind];
      const headers = { 'x-fncp-gateway-key': gatewaySecret, 'x-fncp-conversation-id': conversationId, 'x-fncp-participant-xid': xid };
      const suffix = kind === 'vote' ? '' : '?' + new URLSearchParams({ conversation_id: conversationId, lang: 'en', agid: '1' });
      const result = await perform(route + suffix, kind === 'vote' ? 'POST' : 'GET', headers,
        kind === 'vote' ? { conversation_id: conversationId, tid: values.tid, vote: values.vote } : undefined);
      if (result.status !== 200) {
        if (result.status === 403) throw Object.assign(new Error('Participation denied.'), { status: 403, outcome: 'unconfirmed' });
        if (result.status === 400) throw Object.assign(new Error('Invalid participation request.'), { status: 400, outcome: 'unconfirmed' });
        throw unavailable();
      }
      const value = result.body;
      if (!plain(value)) throw unavailable();
      if (kind === 'next') {
        if (value.tid === undefined && value.txt === undefined) {
          if (Object.keys(value).some(k => !['auth', 'currentPid'].includes(k))) throw unavailable();
          return Object.freeze({});
        }
        return statement(value);
      }
      const nextComment = statement(value.nextComment ?? null);
      if (kind === 'vote') {
        if (!Object.hasOwn(value, 'nextComment') && Object.keys(value).some(k => !['auth', 'currentPid', 'shouldMod', 'modOptions'].includes(k))) throw unavailable();
        return Object.freeze({ nextComment });
      }
      if (!Object.hasOwn(value, 'nextComment') || !Array.isArray(value.votes) || value.votes.length > 15
        || value.conversation !== undefined && (!plain(value.conversation) || value.conversation.conversation_id !== conversationId)) throw unavailable();
      const votes = value.votes.map(v => {
        if (!plain(v) || !tids.has(v.tid) || ![-1, 0, 1].includes(v.vote)) throw unavailable();
        return Object.freeze({ tid: v.tid, vote: v.vote });
      });
      if (new Set(votes.map(v => v.tid)).size !== votes.length) throw unavailable();
      return Object.freeze({ nextComment, votes: Object.freeze(votes) });
    },
    close() { closed = true; for (const abort of [...active]) abort(); gatewaySecret = ''; providerSecret = ''; },
  });
  adapters.add(adapter); return adapter;
}
