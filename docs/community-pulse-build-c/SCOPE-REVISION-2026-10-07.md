# Community Pulse — revised purpose and signup direction

7 October 2026, Australia/Sydney. Dean's latest purpose correction supersedes the founder-only purpose used in the earlier first-round planning record. This repository record carries forward the selected scope and prepared design. Migration execution has not been approved or implemented; runtime code, public services and participant records are unchanged.

## Current purpose

**To understand First Nations people's views, priorities and experiences on community issues, policies and decisions affecting them.**

The platform is First Nations Community Pulse. It is not limited to business-founder priorities. The original founder eligibility wording, founder-priority prompt and fifteen business statements cannot be treated as the settled content for this broader purpose. Preserve them as historical material while preparing the revised round.

## Signup findings

Self-hosted Pol.is can be customised. WordPress is a current implementation choice, not a requirement imposed by Pol.is. The upstream [authentication module](https://github.com/compdemocracy/polis/blob/stable/server/src/auth/README.md) supports OIDC and participant tokens; the [configuration guide](https://github.com/compdemocracy/polis/blob/stable/docs/configuration.md#authentication) documents the identity-provider settings.

The preserved WordPress-dependent Build C engineering candidate already gives participants one Community Pulse page for sign-in, declarations, registration status, private-code redemption and voting. Participants do not register a WordPress user account or visit WordPress admin. WordPress is a private staff approval/registration service reached by authenticated server-to-server calls. The chosen identity provider manages login/account creation and may use its own branded redirect page.

**Selected by Dean: “Remove WordPress.”** The target is native registration, consent and staff approval inside the Community Pulse application, with self-hosted Pol.is voting/analysis. The [native migration plan](NATIVE-MIGRATION-PLAN-2026-10-07.md) specifies the new authority, staff controls, schema, installation and recovery work. Its state is **selected; execution pending exact approval**. Current WordPress-dependent code/services/data have not been migrated or removed.

The target must use a distinctly versioned native authority, not a WordPress-branded replacement object or simulated WordPress status. The existing staff/session/approval/revocation/recovery controls must be replaced explicitly. Signup can remain one participant journey; sign-in, consent and server-enforced permission are still separate checks inside the application.

## Questions awaiting Dean's choice

1. **First-pilot audience:** recommended—Aboriginal and Torres Strait Islander adults currently in Australia, with no founder requirement. Alternative—Indigenous adults internationally, requiring country/community criteria to be redesigned. Keep the existing 18+ boundary unless Dean changes it.
2. **Signup architecture: answered.** WordPress-free Community Pulse is selected. The remaining execution choice is the bounded migration plan, not another platform selection.

The confirmed purpose may be drafted now. Audience-dependent wording/topics await the audience choice; changing the approval authority awaits the exact migration approval. The existing maximum-20 registration and fixed-15 statement constraints remain technical pilot limits while the broader round is defined; they are not limits of Pol.is itself.

The original founder-round ID, provisional dates and derived deletion deadlines belong to that original record. A broader round must have its own reviewed topic/copy, valid window and matching retention record before opening; no automatic launch, postponement or deletion occurs here. The previous source verification remains evidence of technical components, not approval of the revised community/policy content.
