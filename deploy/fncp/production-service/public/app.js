'use strict';
// Invitations are entered manually. Clear unrecognized URL fragments before
// the first request; neither login callbacks nor invitation tokens are stored.
if (location.hash) history.replaceState(null, '', location.pathname);
const $ = id => document.getElementById(id);
let csrf = ''; let state; let notice; let currentTid = null; let busy = false;
let registrationUncertain = false;

function message(text, error = false) { $('status').textContent = text; $('status').classList.toggle('error', error); }
function controls(value) {
  busy = value; $('workspace').setAttribute('aria-busy', String(value));
  document.querySelectorAll('button,input').forEach(element => { element.disabled = value; });
}
async function api(path, values) {
  const response = await fetch(path, { method: values === undefined ? 'GET' : 'POST',
    mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...(values === undefined ? {} : { 'Content-Type': 'application/json' }) },
    ...(values === undefined ? {} : { body: JSON.stringify(values) }) });
  const value = await response.json();
  if (!response.ok) { const error = new Error(value.error || 'The outcome could not be confirmed. No automatic retry was made.'); error.status = response.status; throw error; }
  return value;
}
function applyState(value) {
  const wasAuthenticated = state?.authenticated === true;
  state = value; csrf = value.csrf; notice = value.registrationNotice;
  const authenticated = value.authenticated === true;
  const reference = authenticated && typeof value.registrationReference === 'string' ? value.registrationReference : '';
  $('registration-reference').hidden = !reference;
  $('registration-reference').textContent = reference ? `Your registration reference: ${reference}. Use it when contacting the round operator; it does not grant participation access.` : '';
  const participant = authenticated && value.participationSession === true;
  const phase = participant ? 'participate' : !authenticated ? 'signin' : ['unregistered', 'unconfirmed'].includes(value.registrationState) ? 'register' : 'invite';
  for (const step of ['signin', 'register', 'invite', 'participate']) {
    if (step === phase) $(`step-${step}`).setAttribute('aria-current', 'step'); else $(`step-${step}`).removeAttribute('aria-current');
  }
  $('stage').textContent = { signin: 'SIGN IN', register: 'REGISTER', invite: 'CURRENT ROUND STATUS', participate: 'PARTICIPATE' }[phase];
  $('panel-title').textContent = { signin: 'Sign in to begin', register: 'Your registration', invite: 'Approval and invitation', participate: 'Consider this statement' }[phase];
  $('login-form').hidden = authenticated;
  $('logout').hidden = !authenticated;
  $('registration-form').hidden = !authenticated || !['unregistered', 'unconfirmed'].includes(value.registrationState) || registrationUncertain || !notice;
  $('waiting').hidden = !authenticated || (['unregistered', 'unconfirmed'].includes(value.registrationState) && !registrationUncertain) || participant;
  $('invite-form').hidden = !authenticated || value.registrationState !== 'approved' || !value.roundOpen || participant;
  $('vote-panel').hidden = !participant;
  $('registration-state').textContent = registrationUncertain ? 'Registration outcome is unconfirmed. Check current status before choosing whether to retry with this account.'
    : value.registrationState === 'unconfirmed' ? 'WordPress has not confirmed this registration. Review the declarations and submit again to retry with this account.'
    : value.registrationState === 'pending' ? 'Registration received. You are waiting for a separate round decision; this does not approve participation.'
      : value.registrationState === 'revoked' ? 'Participation is closed for this account. Contact the round operator if you need help.'
        : value.roundOpen ? 'Your account is approved. Enter its invitation to continue.' : 'Your account is approved, but the round is closed. An invitation cannot open a closed round.';
  if (notice) {
    $('adult-declaration').textContent = notice.adultDeclaration;
    $('eligibility-declaration').textContent = notice.eligibilityDeclaration;
    $('consent-declaration').textContent = notice.registrationDeclaration;
  }
  if (!authenticated || !wasAuthenticated) for (const id of ['adult', 'eligibility', 'consent']) $(id).checked = false;
  if (!authenticated) { $('invitation').value = ''; $('statement').textContent = ''; currentTid = null; }
}
function statement(value, focus = false) {
  currentTid = value.statement?.tid ?? null;
  $('statement').textContent = value.statement?.text ?? '';
  $('statement').hidden = currentTid === null; $('vote-actions').hidden = currentTid === null; $('complete').hidden = currentTid !== null;
  if (focus) (currentTid === null ? $('complete') : $('statement')).focus();
}
async function action(operation) {
  if (busy) return; controls(true);
  try { await operation(); }
  catch (error) {
    currentTid = null; $('vote-actions').hidden = true;
    message(error.message || 'The outcome could not be confirmed. No automatic retry was made.', true); $('status').focus();
    // These are read-only status checks. Never repeat registration, redemption
    // or a vote after an uncertain response.
    if ([401, 403].includes(error.status)) {
      try { applyState(await api('/session')); } catch {
        // A revoked account may still own its browser session. Keep its
        // synchronizer so an explicit Sign out can clear that session.
      }
    }
  } finally { controls(false); }
}
$('login-form').addEventListener('submit', event => {
  event.preventDefault(); void action(async () => {
    const value = await api('/oidc/login', {});
    const target = new URL(value.authorizationUrl);
    if (target.protocol !== 'https:' || target.username || target.password || target.hash) throw new Error('Sign-in unavailable.');
    csrf = ''; message('Continuing to the identity service…'); location.assign(target.href);
  });
});
$('registration-form').addEventListener('submit', event => {
  event.preventDefault(); void action(async () => {
    if (!notice || !$('adult').checked || !$('eligibility').checked || !$('consent').checked) throw new Error('Read and confirm each declaration separately.');
    try {
      const value = await api('/registration', { consentVersion: notice.consentVersion, adultSelfAttested: true,
        eligibilitySelfAttested: true, registrationConsent: true });
      applyState({ ...value, registrationNotice: notice }); message('Registration received. A separate round approval and account-bound invitation are still required.');
    } catch (error) { registrationUncertain = true; applyState(state); throw error; }
  });
});
$('check-status').addEventListener('click', () => { void action(async () => {
  const value = await api('/session');
  registrationUncertain = false;
  applyState(value); message(value.registrationState === 'unconfirmed' ? 'Registration is still unconfirmed. You can review the declarations and submit again with this account.' : 'Current registration and round status checked.');
}); });
$('invite-form').addEventListener('submit', event => {
  event.preventDefault(); const invitationToken = $('invitation').value; $('invitation').value = '';
  void action(async () => {
    await api('/invitations/redeem', { invitationToken });
    applyState(await api('/session')); statement(await api('/polis/participation-init'), true);
    message('Choose Agree, Disagree or Pass for the displayed statement.');
  });
});
document.querySelectorAll('[data-vote]').forEach(button => button.addEventListener('click', () => {
  if (currentTid === null || busy) return;
  const tid = currentTid; currentTid = null;
  void action(async () => {
    const value = await api('/polis/votes', { tid, vote: Number(button.dataset.vote) });
    statement(value, true); message(value.complete ? 'Response recorded. No further statements are available.' : 'Response recorded. Consider the next statement.');
  });
}));
$('next').addEventListener('click', () => { void action(async () => {
  statement(await api('/polis/next-comment'), true); message('Current available statement checked.');
}); });
$('logout').addEventListener('click', () => { void action(async () => {
  try { await api('/session/logout', {}); }
  finally { csrf = ''; currentTid = null; registrationUncertain = false; $('invitation').value = ''; $('statement').textContent = ''; }
  applyState(await api('/session')); message('Signed out of this browser session.');
}); });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
void action(async () => {
  applyState(await api('/session'));
  if (state.participationSession) statement(await api('/polis/participation-init'));
  message(state.authenticated ? 'Current account status checked.' : 'Ready. Sign in with your own account.');
});
