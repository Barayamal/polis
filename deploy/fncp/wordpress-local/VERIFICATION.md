# Local WordPress adapter verification

Recorded: **2026-09-13T12:33:45+10:00** (Australia/Sydney).

Scope: the new disposable local WordPress 7.1 installation, host PHP 8.5.10,
local receiver `127.0.0.1:8101`, and explicitly synthetic fixtures only. No live
WordPress/Jetpack source or real registration content was used.

## Completed

- **23/23** pure contract/journal model checks passed.
- **13/13** WordPress adapter stub/model boundary checks passed.
- The first real WordPress + receiver integration run passed **12/12** checks.
  It persisted approval version 1, obtained its matching signed-event receiver
  acknowledgement, persisted revocation version 2, obtained that acknowledgement,
  reloaded the journal and verified terminal revocation.
- An additional real subscriber capability check was added after the first run.
  The authorization-only rerun passed **6/6** checks, including that new boundary:
  a subscriber holding a valid action nonce cannot approve or revoke. The other
  five authorization checks repeat the first run and are not six extra unique
  end-to-end checks. The integration script now contains **13 unique checks**.
- PHP syntax checks passed; `git diff --check` passed for this new directory.
- Calling the integration script without the exact approved disposable bootstrap
  path failed closed before loading WordPress.

## Browser QA correction

Actual browser use subsequently exposed a form-shape defect not covered by the
earlier CLI approval calls: WordPress's default `submit_button()` adds a named
`submit` field, while the strict handlers correctly rejected that extra field.
Both buttons now explicitly omit their name; the handlers' narrow whitelists
were not broadened. Reloading the administrator page is required before retrying
a form already rendered with the earlier button.

The real WordPress test now renders the page with the actual WordPress helper
and parses both forms. Its three added checks verify that exactly two forms are
present and that each form's successful named controls match its handler's exact
schema. The authorization/form-shape rerun passed **9/9**, without sending any
approval event. The current full integration script contains **16 unique checks**;
it has not been rerun as a complete 16-check mutation sequence against the already
revoked one-shot fixture. Browser end-to-end outcomes are recorded separately by
the parent task.

## Retained synthetic state

The integration fixture `synthetic_wp_integration` is revoked. Its approval and
revocation event records are retained in `fncp_wp_local_journal_v1`, both marked
acknowledged. No journal reset or deletion was performed. A local WordPress user
`synthetic_wp_subscriber` was created with subscriber role, empty email and a
random undisplayed password for the capability test.

The authorization-only rerun generated no approval event. The disposable runtime
also blocks all mail and all WordPress HTTP destinations other than the exact
local receiver. No public service was contacted by these integration tests.

## What these results do not establish

These checks establish the local PHP capability/nonce, durable journal and signed
receiver path. They do not alone establish the full browser login and voter UI,
real email ownership, production transport, cross-store atomic revocation,
deployment-wide closure, complete Pol.is warm-session assurance, eligibility
policy, a live installation, or launch authority. Those are separately tested or
remain separate owner-approved production work. This is local Barayamal adapter
code built alongside the Pol.is self-hosted proof, not an upstream supplied plugin.
