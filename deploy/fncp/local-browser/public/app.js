'use strict';
// Fragments never reach HTTP. Clear immediately, before any fetch or UI action.
let pendingInvitation = new URLSearchParams(location.hash.slice(1)).get('invite') ?? '';
if (location.hash) history.replaceState(null, '', location.pathname);
if (!/^[A-Za-z0-9_-]{32,512}$/u.test(pendingInvitation)) pendingInvitation = '';
const $ = (id) => document.getElementById(id);
let csrf = ''; let phase = 'visitor'; let currentTid = null; let busy = false; let focusAfter = null; let oidc = false;
let registrationEnabled = false; let registrationStatus = 'NOT_SUBMITTED'; let invitationRequested = false;
let httpsRedirect = false;

function message(text, error = false) {
  $('status').textContent = text;
  $('status').classList.toggle('error', error);
}
function controls(disabled) {
  busy = disabled;
  document.querySelectorAll('button, input').forEach((element) => { element.disabled = disabled; });
  $('workspace')?.setAttribute('aria-busy', String(disabled));
}
function applyState(state) {
  const oldPhase = phase;
  csrf = state.csrf; phase = state.phase;
  oidc = state.authentication === 'SIGNED_SYNTHETIC_OIDC';
  httpsRedirect = state.authenticationTransport === 'HTTPS_REDIRECT_LAB';
  $('oidc-start-help').textContent = httpsRedirect
    ? 'This local HTTPS lab opens an invented identity issuer and returns here automatically. It does not use a real identity service or verify mailbox ownership or Indigenous heritage. Do not paste a callback or bypass any browser security warning.'
    : 'This mode verifies signed, invented OIDC identities. A private in-process test driver supplies the synthetic response. It does not connect to a real identity service or verify mailbox ownership or heritage.';
  registrationEnabled = state.registrationEnabled === true;
  registrationStatus = state.registrationStatus ?? 'NOT_SUBMITTED';
  if (phase === 'visitor' || oldPhase === 'visitor') {
    invitationRequested = false;
    for (const id of ['registration-adult', 'registration-eligibility', 'registration-consent']) $(id).checked = false;
  }
  if (phase === 'visitor' && oldPhase !== 'visitor') {
    $('invitation').value = ''; $('oidc-callback').value = ''; pendingInvitation = '';
  }
  $('login-form').hidden = phase !== 'visitor' || oidc;
  $('oidc-start-form').hidden = phase !== 'visitor' || !oidc || state.oidcPending;
  $('oidc-callback-form').hidden = httpsRedirect || phase !== 'visitor' || !oidc || !state.oidcPending;
  const registrationStage = registrationEnabled && phase === 'authenticated';
  const submitted = registrationStatus === 'SUBMITTED_NOT_APPROVED';
  const uncertain = registrationStatus === 'OUTCOME_UNCONFIRMED';
  $('registration-form').hidden = !registrationStage || registrationStatus !== 'NOT_SUBMITTED';
  $('registration-result').hidden = !registrationStage || (!submitted && !uncertain);
  $('registration-result-title').textContent = uncertain ? 'Registration outcome unconfirmed' : 'Registration submitted — not approved';
  $('registration-result-copy').textContent = uncertain ? 'Your registration may already be recorded. Do not resubmit or change accounts to try again. Ask the local operator to check first.' :
    'A separate Barayamal round decision and an account-bound invitation are still required. No email or message has been sent.';
  $('registration-reference-line').hidden = !submitted;
  $('registration-reference').textContent = submitted ? state.registrationId ?? '' : '';
  $('show-invitation').hidden = !submitted || invitationRequested;
  $('invite-form').hidden = phase !== 'authenticated' || (registrationEnabled && (!submitted || !invitationRequested));
  $('vote-panel').hidden = phase !== 'participant';
  $('logout').hidden = phase === 'visitor' && !state.oidcPending;
  $('logout').textContent = phase === 'visitor' && state.oidcPending ? 'Cancel synthetic sign-in' : 'Log out';
  $('panel-title').textContent = registrationStage && !invitationRequested ? 'Register your invented account' : { visitor: 'Start with your synthetic account', authenticated: 'Unlock your account-bound invitation', participant: 'Make your voice count — synthetically' }[phase];
  $('step-register').hidden = !registrationEnabled;
  $('number-invite').textContent = registrationEnabled ? '3' : '2'; $('number-vote').textContent = registrationEnabled ? '4' : '3';
  const currentStep = phase === 'visitor' ? 'step-login' : phase === 'participant' ? 'step-vote' : registrationStage && !invitationRequested ? 'step-register' : 'step-invite';
  for (const id of ['step-login', 'step-register', 'step-invite', 'step-vote']) {
    if (id === currentStep) $(id).setAttribute('aria-current', 'step'); else $(id).removeAttribute('aria-current');
  }
  if (phase === 'authenticated' && pendingInvitation) {
    $('invitation').value = pendingInvitation; pendingInvitation = '';
  }
}
async function api(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? 'GET' : 'POST', mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: body === undefined ? {} : { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const result = await response.json();
  if (!response.ok) { const error = new Error(result.error ?? 'The local request could not be confirmed.'); error.status = response.status; throw error; }
  return result;
}
function showStatement(result, focus = false) {
  currentTid = result.statement?.tid ?? null;
  $('statement').textContent = result.statement?.text ?? '';
  $('statement').hidden = currentTid === null;
  $('vote-actions').hidden = currentTid === null;
  $('complete').hidden = currentTid !== null;
  if (focus) focusAfter = currentTid === null ? 'complete' : 'statement';
}
async function refresh(initialize = false, focus = false) {
  const result = await api(initialize ? '/api/participation-init' : '/api/next-comment');
  showStatement(result, focus);
  message(result.complete ? 'Your synthetic account has no further statements to respond to.' : 'Choose Agree, Disagree or Pass. Only the displayed fixed statement can be submitted.');
}
async function recover(error) {
  currentTid = null; $('vote-actions').hidden = true;
  if ([401, 403].includes(error.status)) {
    try { applyState(await api('/api/session')); } catch { csrf = ''; }
  }
  message(error.message || 'The request could not be confirmed. Do not resubmit automatically.', true);
  focusAfter = 'status';
}
async function action(fn) {
  if (busy) return;
  controls(true);
  try { await fn(); } catch (error) { focusAfter = null; await recover(error); } finally {
    controls(false);
    if (focusAfter) { $(focusAfter).focus(); focusAfter = null; }
  }
}
$('login-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const fixture = $('fixture').value; const fixtureSecret = $('fixture-secret').value;
  $('fixture-secret').value = '';
  void action(async () => {
    applyState(await api('/api/login', { fixture, fixtureSecret }));
    message('Synthetic sign-in complete. Mailbox ownership and heritage are still not verified.');
    focusAfter = registrationEnabled ? 'registration-adult' : 'invitation';
  });
});
$('oidc-start-form').addEventListener('submit', (event) => {
  event.preventDefault();
  void action(async () => {
    const result = await api('/api/oidc/start', {});
    applyState(result);
    if (httpsRedirect) {
      const target = new URL(result.authorizationUrl);
      if (location.protocol !== 'https:' || target.protocol !== 'https:' || !target.hostname.endsWith('.invalid') ||
          target.hostname === location.hostname || target.username || target.password || target.hash) throw new Error('Synthetic HTTPS redirect unavailable.');
      message('Opening the invented local identity issuer. This is not real identity or heritage verification.');
      // Explicit top-level navigation. The API client never follows redirects.
      location.assign(target.href);
      return;
    }
    message('Waiting for an explicit invented response from the private local test driver. No real sign-in request was sent.');
    focusAfter = 'oidc-callback';
  });
});
$('oidc-callback-form').addEventListener('submit', (event) => {
  event.preventDefault(); const callbackUrl = $('oidc-callback').value; $('oidc-callback').value = '';
  void action(async () => {
    applyState(await api('/api/oidc/callback', { callbackUrl }));
    message('Synthetic signed identity verified. Separate current round approval and an account-bound invitation are still required.');
    focusAfter = registrationEnabled ? 'registration-adult' : 'invitation';
  });
});
$('registration-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const input = { adultSelfAttested: $('registration-adult').checked, eligibilitySelfAttested: $('registration-eligibility').checked,
    registrationConsent: $('registration-consent').checked, consentVersion: 'synthetic-registration-v1' };
  void action(async () => {
    if (!input.adultSelfAttested || !input.eligibilitySelfAttested || !input.registrationConsent) {
      message('Confirm all three declarations before submitting the invented registration.', true); focusAfter = 'registration-adult'; return;
    }
    message('Recording the synthetic registration. Please wait; do not submit again.');
    try {
      applyState(await api('/api/registration', input));
      message('Registration recorded. You are not approved to vote. Wait for the separate local operator decision.');
      focusAfter = 'registration-result-title';
    } catch (error) {
      try { applyState(await api('/api/session')); } catch { /* A lost reply may follow a committed registration. */ }
      if (phase === 'authenticated') {
        $('registration-form').hidden = true; $('registration-result').hidden = false;
        $('registration-result-title').textContent = 'Registration outcome unconfirmed';
        $('registration-result-copy').textContent = 'It may already be recorded. Do not resubmit or change accounts to try again. Ask the local operator to check first.';
        $('show-invitation').hidden = true; $('invite-form').hidden = true;
      }
      message(error.message || 'Registration outcome unconfirmed. Ask the local operator to check.', true); focusAfter = 'status';
    }
  });
});
$('show-invitation').addEventListener('click', () => {
  if (!registrationEnabled || registrationStatus !== 'SUBMITTED_NOT_APPROVED' || phase !== 'authenticated') return;
  invitationRequested = true; $('show-invitation').hidden = true; $('invite-form').hidden = false;
  $('panel-title').textContent = 'Unlock your account-bound invitation';
  $('step-register').removeAttribute('aria-current'); $('step-invite').setAttribute('aria-current', 'step');
  $('invitation').focus();
});
$('invite-form').addEventListener('submit', (event) => {
  event.preventDefault(); const invitationToken = $('invitation').value; $('invitation').value = ''; pendingInvitation = '';
  void action(async () => { applyState(await api('/api/redeem', { invitationToken })); await refresh(true, true); });
});
for (const button of document.querySelectorAll('[data-vote]')) button.addEventListener('click', () => {
  if (currentTid === null) return;
  const tid = currentTid; const vote = Number(button.dataset.vote); currentTid = null;
  void action(async () => { const result = await api('/api/votes', { tid, vote }); showStatement(result, true); message(result.complete ? 'Response saved. No further statements are available for this account.' : 'Response saved. Here is the next fixed synthetic statement.'); });
});
$('refresh').addEventListener('click', () => { void action(() => refresh(false, true)); });
$('logout').addEventListener('click', () => { void action(async () => {
  const result = await api('/api/logout', {}); csrf = ''; currentTid = null; pendingInvitation = '';
  $('fixture').value = ''; $('fixture-secret').value = ''; $('invitation').value = ''; $('statement').textContent = '';
  $('oidc-callback').value = '';
  applyState(await api('/api/session'));
  message(result.backendLogoutVerified ? 'Logged out of this local browser session.' : 'Browser session closed. Backend logout was not confirmed; no access is retained in this browser service.');
  focusAfter = 'status';
}); });
window.addEventListener('pageshow', (event) => { if (event.persisted) location.reload(); });
void action(async () => {
  applyState(await api('/api/session'));
  if (phase === 'participant') await refresh(true);
  else if (registrationEnabled && phase === 'authenticated') message(registrationStatus === 'SUBMITTED_NOT_APPROVED'
    ? 'Registration is submitted, not approved. A separate local operator decision is still required.'
    : registrationStatus === 'OUTCOME_UNCONFIRMED' ? 'Registration outcome is unconfirmed. Do not resubmit; ask the local operator to check.'
    : 'Read and confirm the three declarations for this invented registration. Registration does not grant voting access.');
  else message(pendingInvitation ? 'A local invitation was loaded and removed from the address bar. Sign in with its matching synthetic account.' :
    oidc ? 'Ready for a signed synthetic identity check. No real identity service, mailbox verification or public consultation is enabled.' : 'Ready. Use only the private invented credentials provided by your local test operator.');
});
