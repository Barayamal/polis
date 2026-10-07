/** Actual loopback WordPress HTTP helper; cookies, CSRF and receipts stay private. */
export function createWordPressIdentityClient(origin = 'http://127.0.0.1:8103', operator = undefined) {
  if (origin !== 'http://127.0.0.1:8103') throw new Error('Exact fresh WordPress origin required.');
  let cookie = ''; let csrf = '';
  const call = async (action, fields, adminCookie) => {
    const response = await fetch(origin + '/wp-admin/admin-post.php' + (fields === undefined ? '?action=' + action : ''), {
      method: fields === undefined ? 'GET' : 'POST', redirect: 'error', signal: AbortSignal.timeout(12_000),
      headers: { 'Sec-Fetch-Site': 'same-origin', 'Sec-Fetch-Mode': 'same-origin', 'Sec-Fetch-Dest': 'empty',
        ...(fields === undefined ? {} : { Origin: origin, 'Content-Type': 'application/x-www-form-urlencoded' }),
        ...(adminCookie ?? cookie ? { Cookie: adminCookie ?? cookie } : {}) },
      ...(fields === undefined ? {} : { body: new URLSearchParams({ action, ...fields }).toString() }),
    });
    let length = 0; const chunks = [];
    for await (const chunk of response.body ?? []) {
      length += chunk.byteLength; if (length > 32768) throw new Error('Fresh WordPress response exceeded bound.'); chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf8');
    let body; try { body = JSON.parse(raw); } catch { body = { nonJson: true }; }
    for (const value of response.headers.getSetCookie()) {
      if (value.startsWith('fncp_wp_identity=')) cookie = value.split(';')[0];
    }
    if (typeof body.csrfToken === 'string') csrf = body.csrfToken;
    const { csrfToken: omitted, ...safe } = body;
    return { status: response.status, body: safe, noStore: response.headers.get('cache-control')?.includes('no-store') === true };
  };
  return {
    session: () => call('fncp_identity_session'),
    challenge: (extra = {}) => call('fncp_identity_challenge', { csrfToken: csrf, ...extra }),
    register: (receipt, extra = {}) => call('fncp_identity_register', { csrfToken: csrf, receipt: JSON.stringify(receipt), ...extra }),
    decide: (registrationId, state, overrides = {}) => call('fncp_identity_decide', {
      registration_id: registrationId, state, _fncp_nonce: operator?.nonce ?? '', ...overrides }, operator?.cookie ?? ''),
  };
}
