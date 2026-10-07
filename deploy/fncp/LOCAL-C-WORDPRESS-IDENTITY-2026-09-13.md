# C continuation — actual WordPress registration bound to strict synthetic identity

**13 September 2026 · Local invented-data proof complete · Production/launch HOLD**

## Outcome

The fresh WordPress registration/admin/outbox now connects to the previously
tested signed-synthetic identity, account-bound invitation, activation and actual
local Pol.is path. No browser-selected account/fixture is trusted. This closes
the earlier gap between the strict Node identity proof and the separate legacy
WordPress demonstration. It does not turn either into a production service.

- **456/456 combined Node tests passed**, including 28 strict adapter, 32 new
  registration/runtime and 80 strict-recovery checks. These are one combined
  count, not 456 plus those subsets.
- **21/21 new PHP model/boundary tests passed.** The prior 23 journal and 13
  WordPress adapter tests were also rerun successfully: 57 PHP checks total.
- **29 actual WordPress-to-Pol.is journey stages passed**, with additional
  independent final readbacks and store-preservation assertions.
- The actual invocation retained **one invented vote** and **two terminal
  provider identities**. Final aggregate: **0 allowlist rows / 15 fixed seeds /
  31 retained invented vote rows**.
- Fresh WordPress final readback: **2 registrations / 2 approval subjects /
  2 acknowledged terminal revocations / 0 pending events**.
- Original access SQLite bytes and original synthetic WordPress all-table counts
  plus exact approval-journal hash were unchanged. This is not a byte-for-byte
  comparison of the whole WordPress database.

Evidence: [actual integration report](./evidence/wordpress-identity-2026-09-13T04-48-52-296Z.json),
[local source/runtime capture](./evidence/local-wip-2026-09-13T04-49-59-772Z/runtime.json),
[implementation and repeatable commands](./wordpress-identity/README.md),
[strict recovery contract](./strict-recovery/README.md).
The source capture precedes final handoff documentation and is local uncommitted
WIP—not a release signature or a claim that the captured services remain running.

## Implemented and repaired

1. Added a private strict adapter operation that derives the registration fixture
   from the current minted principal/mapping and live auth capability. It works
   while the round is closed but requires current signed authority. Logout,
   revocation, identity expiry, missing mappings and stale generations deny it.
2. Added separately keyed, domain-separated WordPress challenge and BFF receipt
   contracts with exact canonical JSON, purpose/audience/round checks, expiry,
   duplicate-key rejection and explicit type guards.
3. Added independent WordPress guest cookie/CSRF binding, atomic challenge and
   receipt consumption, account-per-round deduplication and immutable consent
   notice/version/acceptance/registration facts. No email or heritage documents.
4. Restricted the fresh administrator handler to stored registration references,
   manage-options capability and a separate WordPress nonce. The old arbitrary
   subject handler is absent, not merely hidden in the UI.
5. Reused the durable signed outbox: actual local PHP sent approval and revocation
   only to the fixed loopback receiver, and ACKs were checked before completion.
6. Added a fresh runtime from the existing checksum-verified WordPress 7.1 archive
   and cached digest-pinned MySQL image. New private stores/volume, no old config,
   uploads or registration records copied. Mail and external HTTP are blocked.
7. Added strict recovery model validation: immutable mapping/key fingerprints,
   terminal WordPress/provider agreement, no live capabilities, fresh boot/recovery
   epoch and preserved activation replay floor/IDs. Success means KEEP_CLOSED.
8. Fixed review findings: regex array coercion, missing duplicate-key regression,
   response streaming limit, configuration-before-temp-allocation order and
   imprecise test labels. Updated the CI definition locally; no remote run.

## Exact limits / challenges

- The OIDC tokens are genuinely signature-verified but come from an intercepted
  invented issuer. No real person, mailbox, IdP login, MFA or recovery is proven.
- Actual WordPress HTTP administrator capability/nonce handling was exercised
  with an invented operator cookie provisioned by a private CLI helper. This is
  not proof of the real operator sign-in experience.
- The new handoff is protocol-level, with envelopes transferred by a test helper.
  A rendered participant registration journey/accessibility review is outstanding.
- A signed receipt is **not encrypted** and can expose its opaque local fixture.
  It is registration-only and lasts at most 60 seconds. It cannot outlive the
  issue-time principal/browser/challenge deadlines, but logout after issue does
  not revoke an offline receipt already held by its owner. It grants no access.
- Self-attestation plus owner round approval is **not heritage verification**.
  No real identifiers, participant content, form12069 records or attachments were
  accessed in this increment.
- New private stores are retained as test evidence. Ephemeral identity/activation
  signing-key lifecycle is not a recoverable production custody design. The new
  strict recovery checks did **not** perform an actual expanded multi-store restore.
- Existing application images are unchanged. Their earlier scan result does not
  cover this new host-side integration. Full image/architecture/security review
  and the existing medium/test-infrastructure issues remain release work.
- A shutdown ordering race interrupted the last two Compose stop acknowledgements
  when the VM began stopping. A separate reconciliation checks the containers
  before the final VM shutdown; see the final handoff note in the owner guide.

## What stayed unchanged

Final shutdown at **2026-09-13T14:54:44+10:00**: 0 running containers observed
before isolated VM shutdown; all 11 loopback ports closed. The stop-ordering race
was reconciled and no stores were deleted.
[Exact shutdown observation](./evidence/wordpress-identity-shutdown-2026-09-13T04-54-44Z.json).

No external correspondence, provider enquiry, GitHub commit/push/PR submission,
cloud provisioning, purchase, publication, public surface edit or participant
invitation. Pulse, results, the live WordPress close notice, technical fallback and
alpha-QA were not modified. Retention remains a separate task requiring its own
current hold check, exact counts and fresh action-time confirmation.

## Next safe steps

1. Complete the seamless local registration interface using the new verified
   protocol and fixed synthetic notice; test real rendering and accessibility.
2. Extend actual coordinated recovery to this registration registry and approval
   journal, strict access/activation stores and Pol.is state. Prove key continuity,
   expiry and replay denial on a fresh isolated restore; keep it closed.
3. Review production-specific identity, operator MFA, delivery/recovery, key custody,
   deployment measurement, partition handling and source/image inclusion.
4. Use the existing owner cost/architecture pack before any real-provider setup or
   deployment. Exact external actions, source sharing, costs and launch require
   Dean's separate approval. No generic “continue” becomes a public launch.

Official guidance used: [Pol.is self-hosting/source](https://github.com/compdemocracy/polis/blob/stable/README.md),
[Pol.is configuration](https://github.com/compdemocracy/polis/blob/edge/docs/configuration.md),
[WordPress nonce security](https://developer.wordpress.org/apis/security/nonces/).
The account/registration/access bridge is custom Barayamal work, not a security
certification supplied by those upstream instructions.
