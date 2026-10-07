/** Execute actual app.js against a small test DOM and in-memory fetch model.
 * Covers state/event/focus intent, NOT rendered browser/accessibility assurance.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createContext, runInContext } from 'node:vm';
import { randomUUID } from 'node:crypto';

const html = readFileSync(new URL('./public/index.html', import.meta.url), 'utf8');
const script = readFileSync(new URL('./public/app.js', import.meta.url), 'utf8');
const css = readFileSync(new URL('./public/style.css', import.meta.url), 'utf8');
const declarationIds = ['registration-adult', 'registration-eligibility', 'registration-consent'];
const authenticated = (extra = {}) => ({ mode: 'SYNTHETIC_ONLY', csrf: 'synthetic_browser_csrf', phase: 'authenticated',
  authentication: 'SIGNED_SYNTHETIC_OIDC', registrationEnabled: true, registrationStatus: 'NOT_SUBMITTED', ...extra });
const visitor = () => authenticated({ phase: 'visitor' });

test('HTTPS profile uses explicit top-level navigation after CSRF JSON start and hides manual callback entry', async () => {
  const authorizationUrl = 'https://identity.issuer.invalid:8443/authorize?state=invented';
  const pending = authenticated({ phase: 'visitor', oidcPending: true, authenticationTransport: 'HTTPS_REDIRECT_LAB', authorizationUrl });
  const h = await ui({ protocol: 'https:', state: { ...pending, oidcPending: false }, fetch: async path =>
    path === '/api/oidc/start' ? { status: 200, body: pending } : undefined });
  h.get('oidc-start-form').emit('submit'); await h.flush();
  assert.deepEqual(h.navigations, [authorizationUrl]);
  assert.equal(h.get('oidc-callback-form').hidden, true);
  assert.equal(h.get('logout').hidden, false);
  const start = h.calls.find(call => call.path === '/api/oidc/start');
  assert.equal(start.init.redirect, 'error'); assert.equal(start.init.credentials, 'same-origin');
  assert.equal(h.calls.some(call => call.path.startsWith('https:')), false);
  assert.match(h.get('status').textContent, /not real identity or heritage verification/u);
});

test('HTTPS help describes automatic invented navigation without asking users to bypass a warning', async () => {
  const h = await ui({ protocol: 'https:', state: authenticated({ phase: 'visitor', authenticationTransport: 'HTTPS_REDIRECT_LAB' }) });
  assert.match(h.get('oidc-start-help').textContent, /returns here automatically/u);
  assert.match(h.get('oidc-start-help').textContent, /Do not paste a callback or bypass any browser security warning/u);
});

test('manual synthetic profile retains distinct private-driver instructions', async () => {
  const h = await ui({ state: visitor() });
  assert.match(h.get('oidc-start-help').textContent, /private in-process test driver/u);
  assert.doesNotMatch(h.get('oidc-start-help').textContent, /returns here automatically/u);
});

for (const [protocol, authorizationUrl] of [['http:', 'https://identity.issuer.invalid/authorize'],
  ['https:', 'https://real-provider.example/authorize'], ['https:', 'https://browser.example.invalid/authorize'],
  ['https:', 'https://identity.issuer.invalid/authorize#secret'], ['https:', 'http://identity.issuer.invalid/authorize']]) {
  test(`HTTPS UI refuses an invalid redirect profile ${protocol} ${authorizationUrl}`, async () => {
    const state = authenticated({ phase: 'visitor', authenticationTransport: 'HTTPS_REDIRECT_LAB' });
    const h = await ui({ protocol, state, fetch: async path => path === '/api/oidc/start'
      ? { status: 200, body: { ...state, oidcPending: true, authorizationUrl } } : undefined });
    h.get('oidc-start-form').emit('submit'); await h.flush();
    assert.deepEqual(h.navigations, []); assert.equal(h.get('status').classList.contains('error'), true);
    assert.equal(h.get('oidc-callback-form').hidden, true);
  });
}

function testDocument(source) {
  const elements = []; const byId = new Map(); const document = { activeElement: undefined };
  class Element {
    constructor(tag, attributes, parent) {
      this.tagName = tag.toUpperCase(); this.attributes = new Map(attributes); this.parentElement = parent;
      this.children = []; this.content = ''; this.value = ''; this.checked = false; this.handlers = new Map(); this.classes = new Set();
      this.dataset = Object.fromEntries(attributes.filter(([key]) => key.startsWith('data-')).map(([key, value]) => [key.slice(5), value]));
      this.classList = { toggle: (name, on) => { if (on) this.classes.add(name); else this.classes.delete(name); }, contains: name => this.classes.has(name) };
    }
    get hidden() { return this.attributes.has('hidden'); }
    set hidden(value) { if (value) { this.attributes.set('hidden', '');
      if (document.activeElement && !document.activeElement.visible()) document.activeElement = document.body;
    } else this.attributes.delete('hidden'); }
    get disabled() { return this.attributes.has('disabled'); }
    set disabled(value) { if (value) this.attributes.set('disabled', ''); else this.attributes.delete('disabled'); }
    get textContent() { return this.content + this.children.map(child => child.textContent).join(''); }
    set textContent(value) { this.content = String(value); this.children = []; }
    set innerHTML(_) { throw new Error('Unsafe HTML insertion reached the model.'); }
    setAttribute(key, value) { this.attributes.set(key, String(value)); }
    getAttribute(key) { return this.attributes.get(key) ?? null; }
    removeAttribute(key) { this.attributes.delete(key); }
    addEventListener(type, handler) { const values = this.handlers.get(type) ?? []; values.push(handler); this.handlers.set(type, values); }
    visible() { for (let item = this; item; item = item.parentElement) if (item.hidden) return false; return true; }
    focus() { if (!this.disabled && this.visible() && (['INPUT', 'BUTTON', 'SELECT', 'TEXTAREA'].includes(this.tagName) || this.attributes.has('tabindex'))) document.activeElement = this; }
    emit(type) { if (type === 'click' && (this.disabled || !this.visible())) return;
      for (const handler of this.handlers.get(type) ?? []) handler({ preventDefault() {} }); }
  }
  const stack = []; const voidTags = new Set(['meta', 'link', 'input', 'br', 'hr', 'img']);
  for (const token of source.match(/<[^>]+>|[^<]+/gu) ?? []) {
    if (token.startsWith('<!')) continue;
    if (token.startsWith('</')) { const tag = token.match(/^<\/([a-z0-9-]+)/iu)?.[1]?.toUpperCase();
      while (stack.length) if (stack.pop().tagName === tag) break; continue; }
    if (token.startsWith('<')) {
      const match = /^<([a-z0-9-]+)([\s\S]*?)\/?>(?:$)/iu.exec(token); if (!match) continue;
      const attributes = [...match[2].matchAll(/([^\s=]+)(?:\s*=\s*"([^"]*)")?/gu)].map(item => [item[1], item[2] ?? '']);
      const element = new Element(match[1], attributes, stack.at(-1));
      elements.push(element); if (element.getAttribute('id')) byId.set(element.getAttribute('id'), element);
      if (element.tagName === 'BODY') { document.body = element; document.activeElement = element; }
      stack.at(-1)?.children.push(element); if (!voidTags.has(match[1].toLowerCase())) stack.push(element);
    } else if (stack.length) stack.at(-1).content += token;
  }
  document.getElementById = id => byId.get(id) ?? null;
  document.querySelectorAll = selector => selector === 'button, input' ? elements.filter(item => ['INPUT', 'BUTTON'].includes(item.tagName)) :
    selector === '[data-vote]' ? elements.filter(item => item.attributes.has('data-vote')) : [];
  return { document, elements, get: id => byId.get(id) };
}

async function ui(options = {}) {
  const dom = testDocument(html); const calls = []; let state = options.state ?? authenticated(); let custom = options.fetch;
  const navigations = [];
  const location = { hash: options.hash ?? '', pathname: '/', protocol: options.protocol ?? 'http:',
    hostname: 'browser.example.invalid', assign(value) { navigations.push(value); }, reload() {} }; let replaced = false;
  const window = { addEventListener() {} };
  const fetch = async (path, init) => {
    const body = init.body ? JSON.parse(init.body) : undefined; calls.push({ path, init, body });
    let result = await custom?.(path, init, body);
    if (!result) {
      if (path === '/api/session') result = { status: 200, body: state };
      else if (path === '/api/registration') { state = authenticated({ registrationStatus: 'SUBMITTED_NOT_APPROVED', registrationId: randomUUID() }); result = { status: 200, body: state }; }
      else if (path === '/api/logout') { state = visitor(); result = { status: 200, body: { backendLogoutVerified: true } }; }
      else throw new Error('Unexpected model endpoint.');
    }
    return { ok: result.status >= 200 && result.status < 300, status: result.status, json: async () => result.body };
  };
  const context = createContext({ document: dom.document, window, location, URL, URLSearchParams, fetch,
    history: { replaceState() { replaced = true; location.hash = ''; } } });
  runInContext(script, context, { filename: 'actual-local-browser-app.js' });
  const flush = async () => {
    for (let attempt = 0; attempt < 100; attempt++) {
      await new Promise(resolve => setImmediate(resolve));
      if (dom.get('workspace').getAttribute('aria-busy') !== 'true') return;
    }
    throw new Error('UI model action did not settle.');
  };
  await flush();
  return { ...dom, calls, flush, navigations, setState(next) { state = next; }, setFetch(fn) { custom = fn; },
    fragmentRemoved: () => replaced && location.hash === '',
    async submit() { dom.get('registration-form').emit('submit'); await flush(); },
    async click(id) { dom.get(id).emit('click'); await flush(); },
    checkAll() { for (const id of declarationIds) dom.get(id).checked = true; } };
}

test('registration DOM presents three unchecked required declarations with notice and no identity/evidence input', async () => {
  const h = await ui(); assert.equal(h.get('registration-form').hidden, false);
  const form = h.get('registration-form');
  const within = item => { for (let node = item; node; node = node.parentElement) if (node === form) return true; return false; };
  const inputs = h.elements.filter(item => item.tagName === 'INPUT' && within(item));
  assert.equal(inputs.length, 3);
  for (const id of declarationIds) { const input = h.get(id); assert.equal(input.checked, false);
    assert.equal(input.getAttribute('type'), 'checkbox'); assert.notEqual(input.getAttribute('required'), null); }
  assert.match(form.textContent, /self-attestations—not verification/u);
  assert.match(form.textContent, /synthetic-registration-v1/u);
  assert.equal(h.get('invite-form').hidden, true); assert.equal(h.get('vote-panel').hidden, true);
  assert.equal(h.get('step-register').getAttribute('aria-current'), 'step');
});

test('missing declarations prevent fetch and leave an explicit error with keyboard focus', async () => {
  const h = await ui(); h.get('registration-adult').checked = true;
  await h.submit(); assert.equal(h.calls.filter(call => call.path === '/api/registration').length, 0);
  assert.equal(h.get('status').classList.contains('error'), true);
  assert.ok(h.document.activeElement === h.get('registration-adult'));
  assert.equal(h.get('workspace').getAttribute('aria-busy'), 'false');
});

test('successful submission sends only three booleans plus notice version and announces submitted, not approved', async () => {
  const h = await ui(); h.checkAll(); await h.submit();
  const submitted = h.calls.find(call => call.path === '/api/registration');
  assert.deepEqual(Object.keys(submitted.body).sort(), ['adultSelfAttested', 'consentVersion', 'eligibilitySelfAttested', 'registrationConsent']);
  assert.equal(submitted.body.adultSelfAttested, true); assert.equal(submitted.body.eligibilitySelfAttested, true);
  assert.equal(submitted.body.registrationConsent, true); assert.equal(submitted.body.consentVersion, 'synthetic-registration-v1');
  assert.equal(submitted.init.mode, 'same-origin'); assert.equal(submitted.init.credentials, 'same-origin'); assert.equal(submitted.init.redirect, 'error');
  assert.equal(h.get('registration-form').hidden, true); assert.equal(h.get('registration-result').hidden, false);
  assert.match(h.get('registration-result-title').textContent, /not approved/u);
  assert.match(h.get('status').textContent, /not approved to vote/u);
  assert.ok(h.document.activeElement === h.get('registration-result-title'));
  assert.equal(h.get('invite-form').hidden, true); assert.equal(h.get('vote-panel').hidden, true);
  assert.equal(h.calls.filter(call => /receipt|challenge|wp-admin/u.test(call.path)).length, 0);
});

test('pending registration disables controls, marks aria-busy and prevents a second UI submit', async () => {
  const h = await ui(); let release;
  const pending = new Promise(resolve => { release = resolve; });
  h.setFetch(path => path === '/api/registration' ? pending : undefined); h.checkAll();
  h.get('registration-form').emit('submit'); h.get('registration-form').emit('submit');
  assert.equal(h.get('workspace').getAttribute('aria-busy'), 'true');
  assert.ok(h.document.querySelectorAll('button, input').every(element => element.disabled));
  assert.equal(h.calls.filter(call => call.path === '/api/registration').length, 1);
  release({ status: 200, body: authenticated({ registrationStatus: 'SUBMITTED_NOT_APPROVED', registrationId: randomUUID() }) });
  await h.flush(); assert.equal(h.get('workspace').getAttribute('aria-busy'), 'false');
  assert.ok(h.document.querySelectorAll('button, input').every(element => !element.disabled));
});

test('invitation entry needs an explicit reveal after registration and moves focus/current stage', async () => {
  const h = await ui(); h.checkAll(); await h.submit();
  assert.equal(h.get('invite-form').hidden, true); const before = h.calls.length;
  await h.click('show-invitation');
  assert.equal(h.get('invite-form').hidden, false); assert.equal(h.get('show-invitation').hidden, true);
  assert.ok(h.document.activeElement === h.get('invitation'));
  assert.equal(h.get('step-register').getAttribute('aria-current'), null);
  assert.equal(h.get('step-invite').getAttribute('aria-current'), 'step');
  assert.equal(h.calls.length, before);
});

test('uncertain registration hides resubmission/invitation, retains no private identifiers and never auto-retries', async () => {
  const h = await ui(); h.checkAll();
  h.setFetch(path => { if (path === '/api/registration') {
    h.setState(authenticated({ registrationStatus: 'OUTCOME_UNCONFIRMED' }));
    return { status: 503, body: { error: 'Registration may already be recorded. Do not resubmit.' } };
  } });
  await h.submit(); await h.flush();
  assert.equal(h.get('registration-form').hidden, true); assert.equal(h.get('registration-result').hidden, false);
  assert.equal(h.get('show-invitation').hidden, true); assert.equal(h.get('invite-form').hidden, true);
  assert.equal(h.get('registration-reference').textContent, '');
  assert.match(h.get('registration-result-title').textContent, /unconfirmed/u);
  assert.match(h.get('registration-result-copy').textContent, /Do not resubmit/u);
  assert.ok(h.document.activeElement === h.get('status')); assert.equal(h.get('status').classList.contains('error'), true);
  assert.equal(h.calls.filter(call => call.path === '/api/registration').length, 1);
  assert.equal(h.calls.filter(call => call.path === '/api/session').length, 2);
});

test('session expiry after possible commit returns to visitor state with cleared declarations and no registration authority', async () => {
  const h = await ui({ hash: '#invite=' + 'b'.repeat(43) }); h.checkAll();
  assert.ok(h.get('invitation').value.length > 0);
  h.get('oidc-callback').value = 'synthetic_private_expired_callback';
  h.setFetch(path => { if (path === '/api/registration') { h.setState(visitor());
    return { status: 401, body: { error: 'Session ended. Registration may already be recorded; ask the local operator.' } }; } });
  await h.submit();
  for (const id of declarationIds) assert.equal(h.get(id).checked, false);
  assert.equal(h.get('registration-form').hidden, true); assert.equal(h.get('registration-result').hidden, true);
  assert.equal(h.get('oidc-start-form').hidden, false); assert.equal(h.get('registration-reference').textContent, '');
  for (const id of ['invitation', 'oidc-callback']) assert.equal(h.get(id).value, '');
  assert.ok(h.document.activeElement === h.get('status'));
  assert.equal(h.calls.filter(call => call.path === '/api/registration').length, 1);
});

test('logout clears declarations, invitation/callback and registration reference without exposing internal identifiers', async () => {
  const h = await ui(); h.checkAll(); await h.submit(); await h.click('show-invitation');
  h.get('invitation').value = 'synthetic_private_invitation'; h.get('oidc-callback').value = 'synthetic_private_callback';
  h.get('logout').focus();
  await h.click('logout');
  for (const id of declarationIds) assert.equal(h.get(id).checked, false);
  for (const id of ['registration-reference', 'statement']) assert.equal(h.get(id).textContent, '');
  for (const id of ['invitation', 'oidc-callback', 'fixture-secret']) assert.equal(h.get(id).value, '');
  assert.equal(h.get('registration-result').hidden, true); assert.equal(h.get('registration-form').hidden, true);
  assert.equal(h.get('oidc-start-form').hidden, false);
  assert.ok(h.document.activeElement === h.get('status'));
  assert.equal(h.calls.filter(call => call.path === '/api/registration').length, 1);
});

test('pending invitation fragment is removed before fetch and never bypasses the registration/reveal stage', async () => {
  const h = await ui({ hash: '#invite=' + 'a'.repeat(43) });
  assert.equal(h.fragmentRemoved(), true); assert.equal(h.get('invite-form').hidden, true);
  assert.ok(h.get('invitation').value === 'a'.repeat(43));
  assert.equal(h.calls.filter(call => call.path === '/api/redeem').length, 0);
  assert.ok(h.calls.every(call => !call.path.includes('invite')));
});

test('initial visitor preserves a fresh fragment through synthetic sign-in without automatically revealing or redeeming it', async () => {
  const h = await ui({ state: visitor(), hash: '#invite=' + 'c'.repeat(43) });
  assert.equal(h.fragmentRemoved(), true); assert.equal(h.get('invitation').value, '');
  h.setFetch(path => {
    if (path === '/api/oidc/start') return { status: 200, body: { ...visitor(), oidcPending: true } };
    if (path === '/api/oidc/callback') return { status: 200, body: authenticated() };
  });
  h.get('oidc-start-form').emit('submit'); await h.flush();
  h.get('oidc-callback').value = 'synthetic_private_callback';
  h.get('oidc-callback-form').emit('submit'); await h.flush();
  assert.ok(h.get('invitation').value === 'c'.repeat(43));
  assert.equal(h.get('oidc-callback').value, '');
  assert.equal(h.get('registration-form').hidden, false); assert.equal(h.get('invite-form').hidden, true);
  assert.equal(h.calls.filter(call => call.path === '/api/redeem').length, 0);
});

test('registration status reference uses textContent and cannot render arbitrary bridge fields as markup', async () => {
  const h = await ui({ state: authenticated({ registrationStatus: 'SUBMITTED_NOT_APPROVED', registrationId: '<img src=x onerror=synthetic_sentinel>',
    fixture: 'synthetic_private_fixture', receipt: 'synthetic_private_receipt', accountId: 'synthetic_private_account' }) });
  assert.equal(h.get('registration-reference').children.length, 0);
  assert.ok(h.get('registration-reference').textContent.startsWith('<img'));
  for (const value of ['synthetic_private_fixture', 'synthetic_private_receipt', 'synthetic_private_account']) assert.equal(h.document.body.textContent.includes(value), false);
});

test('status, result, declarations and responsive styling carry explicit accessibility intent', () => {
  const h = testDocument(html);
  assert.equal(h.get('status').getAttribute('role'), 'status'); assert.equal(h.get('status').getAttribute('aria-live'), 'polite');
  assert.equal(h.get('status').getAttribute('tabindex'), '-1');
  assert.equal(h.get('registration-result-title').getAttribute('tabindex'), '-1');
  assert.equal(h.get('complete').getAttribute('tabindex'), '-1');
  assert.equal(h.get('registration-form').getAttribute('aria-describedby'), 'registration-help registration-version');
  assert.equal(h.get('registration-result').getAttribute('aria-labelledby'), 'registration-result-title');
  assert.match(html, /<legend>Three independent declarations<\/legend>/u);
  assert.match(css, /:focus-visible/u); assert.match(css, /prefers-reduced-motion/u); assert.match(css, /\[hidden\]/u);
  assert.match(css, /max-width:660px/u);
});
