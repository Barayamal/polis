# Node registration bridge — independent review

Scope: `registration-issuer.mjs`, its tests, `wordpress-client.mjs`, `journey.mjs`,
the BFF registration route, the identity foundation's `principalDeadline`, and
the integrated harness's optional WordPress configuration. This is not a review
claim for an actual WordPress deployment, rendered browser, production identity
provider, or a new coordinated restore.

## Outcome

No remaining blocking Node-side access-authority bypass was identified after the
main task applied the corrections below. Registration is not approval, invitation
issuance, participation, mailbox verification or heritage/eligibility verification.

The fixture is derived by the strict adapter from its current private principal
and existing account mapping. Browser-supplied fixture/account/XID fields do not
select it. The BFF requires a current signed-in account, rejects participation-role
sessions on receipt issuance, retains backend tokens privately, and rechecks its
session/principal after asynchronous issuance. `principalDeadline` consults the
identity instance's private WeakMap and returns null for copied/expired principals;
it is not added to the public identity projection.

The signed receipt purpose/audience is registration-specific. It carries a
bounded opaque fixture but no XID or login/participation token. It is authenticated,
**not encrypted**. Its expiry is capped by the WordPress challenge, live principal,
BFF session and 60-second receipt limit. A receipt issued before logout can remain
usable for registration until that expiry; offline verification cannot discover
later logout. Such a receipt must never be described as current access authority.

## Findings corrected during review

1. Signed challenge UUID/browser-binding arrays were accepted through regex string
   coercion. An invented in-memory signed-array reproduction confirmed it. The
   main task added explicit string checks (including returned fixture and signing
   secrets) and signed-array regressions.
2. The duplicate-key test originally did not create duplicate JSON keys. The main
   task added a separately signed raw duplicate-key payload and rejection check.
3. WordPress HTTP response size was checked only after `response.text()` allocated
   the full response. The main task replaced it with a streaming byte limit.
4. Invalid optional WordPress configuration could throw after allocating an empty
   temporary directory outside cleanup. Validation now precedes allocation, and
   the event/challenge/registration keys are required to be distinct.

## Evidence-label recommendations sent to the main task

- The journey assertion `open === false` establishes that the local round is
  closed, not by itself that every possible participant route/session is denied.
  Use a precise label or add independent post-close checks.
- A successful `open=true` request after synthetic activation is a positive-path
  check, not a new negative proof that an absent signature is rejected. The latter
  has separate activation/integrated coverage.
- The receipt test's uncredentialed raw POST omitted cookie and Fetch Metadata as
  well as CSRF. Its 403 should not be described as an isolated wrong-CSRF test.
  Rename that subclaim or use valid surrounding credentials/metadata and vary only
  the CSRF token. Shared BFF CSRF tests are distinct evidence.

## Verification boundary

The registration test suite passed **21/21** at the reviewed revision. The intended
name filter did not exclude its BFF test: that test created and closed its own
temporary access/activation stores, ephemeral API/BFF and synthetic receiver on
8101 via `h.close()`. No actual WordPress, Pol.is, Docker or preserved database was
used. The review itself made no implementation edits outside this review note;
the main task applied the code/test corrections. No external messages were sent.

The current observations do not claim WordPress's durable challenge consumption,
registration uniqueness, administrator-role checks, receipt replay handling or
actual provider revocation have passed their real-runtime proof. Those require
the separately scoped PHP/WordPress integration and its aggregate evidence.
