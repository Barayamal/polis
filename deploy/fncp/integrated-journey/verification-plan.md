# Integrated Option C journey — verification plan

Status: design/review plan, **not evidence that these integrated tests have run**. Existing identity, activation, browser and WordPress proofs are separate evidence until a new integrated run passes. Keep production/public surfaces closed.

## Mandatory chain

Verified in-process OIDC principal → immutable server-side account/round mapping → **present, latest, applied WordPress approval event** → current signed activation plus separately open round → account-bound invitation redemption → opaque server-side participation session → conversation-scoped Pol.is provider allowlist.

Every protected operation must check the current chain, not only login or invitation issuance. Email verification is an issuer claim, **not Indigenous heritage verification or approval to vote**. A forged JSON principal, email match, raw XID, browser-selected fixture, legacy mailbox simulator or ordinary local `open=true` is never a substitute for a missing gate.

## Proposed actual-local proof driver

Use a new `integrated-journey/real-origin-smoke.mjs` only when runtime execution is authorised. This plan does not start services.

1. Verify explicit fixture-only mode, exact `colima-fncp-c-20260913` context, exact Compose labels/container image IDs, loopback Pol.is origin, dedicated synthetic conversation and both provider enforcement settings. Bind signed authority to observed image/config/seed hashes before and after the run. Independently verify the database has exactly the 15 distinct expected fixed seeds before any vote.
2. Create a fresh, private temporary directory with **new access and activation SQLite stores**, ephemeral signer, browser sessions, OIDC keys and a fresh approval event journal. Do not copy/adopt/open the preserved WordPress MySQL or `local-access/.runtime/synthetic.sqlite` for mutation. Guard path aliases/hardlinks and refuse legacy-mode downgrade.
3. Create the existing synthetic OIDC harness with intercepted token/JWKS requests, no external transport. Pass its one identity-foundation instance to the strict controlled gateway. Pass only its private, live principal into `authenticateIdentity`; keep returned fixture-auth tokens, fixture mapping, principals and XIDs in the server/BFF, never a browser response or log.
4. Start only the new strict API/BFF/event receiver on ephemeral loopback ports. A protocol client may exercise cookies/CSRF, but label that **protocol evidence, not rendered-browser evidence**. A separate in-app-browser check is needed for a rendered UX claim.
5. Drive the positive path for two invented identities with distinct issuer subjects. Generate approval/revocation events through the existing local WordPress contract/journal in a new synthetic test store and, where exercised, deliver through the signed receiver. If the driver calls ingestion directly, report it as **in-process event-contract integration**, not actual WordPress transport/UI evidence. Never imply preserved/live WordPress was tested.
6. Obtain a synthetic signed lease, separately open the local round, and **perform a fresh login after this activation/generation synchronisation**. Pre-activation login is a useful negative but its old auth capability is intentionally invalidated. Then approve the intended principal through an acknowledged current event, issue/redeem its account-bound invitation, initialise actual local Pol.is and submit at most one invented vote. Read only the known seed statement for that vote; do not inspect participant response contents. Run the negative matrix below around this path.
7. In `finally`, first close browser/gateway authority and revoke each **newly allocated XID from this run only** through the existing private provider adapter. Verify each readback is absent with terminal operation version 2. An aggregate SQL read may confirm the global synthetic whitelist returned to its pre-run baseline; never revoke an unrelated entry to make cleanup pass.
8. Close every newly created listener, then remove only this run's positively identified temporary stores after cleanup succeeds. Preserve failed-run private diagnostic stores if revocation/listener cleanup cannot be verified; fail the run and report aggregate-only remediation. Do not delete votes, reset/migrate/bootstrap databases, touch the preserved WP/access state, stop unrelated containers or change public services. A successful invented Pol.is vote may remain in the disposable conversation and must be stated explicitly.
9. Retain a private aggregate report: runtime/code/config/seed binding hashes; layer actually exercised; pass/fail test labels; allocated/revoked/readback counts; intended vote-attempt count and aggregate before/after delta if verified; final round closed; no new listeners; preservation guard result. Never retain raw callback/authorisation URLs, cookies, principal/account/XID values, tokens, event bodies, email addresses or secrets in report/log output.

## Test matrix

| Boundary | Exercise | Required result / evidence |
| --- | --- | --- |
| Principal provenance | JSON copy, hand-built object, another identity instance, expired principal, unverified email claim | Denied before mapping/approval/provider calls; generic public error |
| Account stability | Same issuer+subject login twice; email changes; different subject with same email | Same verified identity keeps its mapping; email does not select identity; different subject cannot inherit approval |
| Browser binding | Forward callback/code to another cookie session; callback replay/concurrency; state/nonce/issuer mismatch | One-use callback bound to original server-created session; no authenticated session in the wrong browser |
| Session rotation | Successful login and invitation redemption; replay old cookie/CSRF | New opaque cookie/session; old cookie no longer authoritative; HttpOnly/SameSite and no-store boundaries retained |
| Browser input scope | Caller supplies fixture/account/XID/principal/token/activation/admin fields; duplicate cookie or forbidden origin | Exact-schema rejection; no private/admin route forwarded; no body/URL-driven identity mapping |
| Authentication ≠ approval | Valid principal but no WordPress event; local fixture/admin approval without a WP event | No invitation/redemption/vote; no implicit provider upsert from authentication alone |
| Current event required | Latest event pending/unapplied; conflicting ID/version/digest; wrong round; old approved event after revoke | Deny current access; exact retry reconciles only the original event; stale approval cannot revive state |
| Two-account invitation binding | Both identities approved; send Alice's invitation to Bob | Bob denied; Alice can redeem once; duplicate/concurrent redemption creates at most one current participation session |
| Invitation lifecycle | Expired invite, reissue, used token, fresh login to same account | Expired/replaced/used token denied; stable account mapping does not bypass invitation lifecycle |
| Signed authority | No signature, wrong image/config/seed/conversation/boot/recovery binding, replay/sequence rollback | Ordinary round-open denied; no usable invitation/session/vote; authority remains fail-closed |
| Positive actual origin | Valid identity + acknowledged approval + current lease + open round + matching invitation | Actual local Pol.is init succeeds; at most one invented fixed-statement vote; no tokens/identifiers in BFF result |
| Principal expiry during await | Expire identity before dispatch and while provider response is in flight | No future dispatch; withhold result/usable session after expiry. Do not claim rollback of a vote already accepted upstream |
| Lease/generation change during await | Expiry, replacement lease or close while issuing/redeeming/participating | Recheck before returning authority; invalidate old local auth/invitations/sessions; new lease does not revive old capabilities |
| Revocation and warm sessions | Revoke acknowledged event while browser remains logged in; simulate provider-removal failure | Local deny commits first; later requests denied even if provider cleanup needs retry; eventual exact removal readback verified |
| Logout | Browser logout, stale cookie, backend outage during logout | Local session immediately dead; old browser token inaccessible; backend-cleanup uncertainty reported honestly |
| Restart/recovery | Restart strict wrapper using only its new temporary stores; stale lease/cookie/auth/participation tokens | Starts closed; new boot authority required; old principal capabilities/session tokens do not revive |
| Errors/replay | Timeout or lost vote response; malformed provider body; oversized request/response; extra fields | No automatic vote/grant retry; display slot cleared on uncertain vote; generic redacted errors |
| Cleanup/preservation | Failure at each setup/approval/vote/close phase | Revoke only run-allocated XIDs; original WP/access state untouched; close only run listeners; aggregate evidence distinguishes incomplete cleanup |

## Review priorities for the new adapter

The old standalone event gate deliberately permits a fixture with no WordPress event; the strict integrated mode must override that with mandatory event presence. The old fixture-auth HTTP simulator and ordinary fixture creation routes must be unavailable in the strict mode. Principal capabilities must remain live in memory and be checked before **and after** asynchronous provider work, including auth/invitation paths where a capability could otherwise outlive its issuer proof. Persistent identity mappings must be one-to-one per account and round, with missing/inconsistent mapping or approval-XID failures rather than silent remapping. Activation changes must invalidate both old browser-held sessions and gateway authority.

The strict local adapter intentionally retains direct authenticated `test-admin/approve` as a **provider-state-only test exception**: it can upsert the mapped identity under current identity/activation checks, but cannot alone authorise invitation issuance, redemption or participation without the current applied WordPress event. The proof must exercise this negative explicitly and must not claim that every provider upsert originates from WordPress. Authentication alone still performs no provider operation.

The maintained local identity module already verifies signed OIDC tokens with exact configured endpoints, PKCE/state/nonce and response issuer. The integrated BFF must preserve those guarantees rather than decoding claims itself or sending its internal principal through JSON. A real OIDC redirect/cookie policy is separate from the `.invalid` intercepted harness; local HTTP cannot claim production Secure-cookie/TLS assurance.

## No-production boundary and remaining work

This run supplies no real identity provider, provider client registration, production callback/TLS, mailbox access service, Indigenous eligibility/heritage determination, participant notification, DPA/terms acceptance, external hosting or launch authority. It sends no email/SMS or provider correspondence. The synthetic signer is not Dean's approval. PR #27 and a passing proof are not GO authority. Existing public Pulse/results/WordPress close notice/technical fallback remain unchanged.

The prior coordinated recovery proof covers an earlier three-store snapshot. It does not cover newly integrated identity mappings, new activation ledgers or later invented votes unless a separately updated recovery contract is implemented and verified.

Primary references: [OpenID Connect claim stability](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability), [OAuth security best current practice](https://www.rfc-editor.org/rfc/rfc9700.html), [authorization-response issuer identification](https://www.rfc-editor.org/rfc/rfc9207.html). Implementation references are the checked-in `identity-foundation`, `activation-foundation`, `local-access`, `wordpress-local` and `local-browser` modules; this plan does not claim upstream Pol.is supplies the full approval workflow.
