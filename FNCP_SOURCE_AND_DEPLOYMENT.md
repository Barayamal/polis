# Barayamal First Nations Community Pulse source and deployment notice

This fork is based on the Computational Democracy Project Pol.is `edge` branch
at commit `424dcae02f0147723a19103dd2d971f6ec1b6db5`.

Pol.is is licensed under the GNU Affero General Public License version 3, with
the additional permission recorded in the upstream `LICENSE` file. Barayamal's
deployed Pol.is modifications, build instructions and deployment configuration
are available without charge from:

<https://github.com/Barayamal/polis>

The First Nations Community Pulse registration and eligibility-review system is
a separate service. Names, email addresses, eligibility answers, attachments
and family/community information must not be copied into this repository or
sent to Pol.is.

## Modified deployment purpose

Barayamal's changes are limited to the self-hosted access and deployment work
needed for a private, consent-bound First Nations Community Pulse round. Each
deployed release must record:

- the exact upstream base commit;
- the exact deployed Barayamal fork commit;
- container/image digests;
- the gateway policy version;
- database migration state;
- the participant-notice/consent version; and
- non-identifying QA evidence.

No genuine-participant deployment is approved by this notice. Production
approval requires the negative access, immediate revocation, backup restore and
deletion matrices to pass against the exact release.
