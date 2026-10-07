# Synthetic registration notice — synthetic-registration-v1

This version applies only to invented local test accounts. It is not approved
participant-facing wording and does not reopen registration.

The three independent statements represented by the receipt are:

1. **Adult self-attestation:** “For this invented test, I self-attest that I am at least 18 years old.”
2. **Eligibility self-attestation:** “For this invented test, I self-attest that I meet the First Nations round eligibility described by Barayamal.”
3. **Registration consent:** “I agree to this invented registration being recorded locally with my opaque account reference, these three declarations, this notice version and timestamps, for Barayamal’s round-approval test.”

None is preselected. All must be exactly true in the synthetic protocol.
An identity service’s email-verification claim is separate and does not verify
age, Indigenous heritage, eligibility or Barayamal approval. No ancestry
documents, email address, contact list or real participant record belongs here.

The tested API binds `consentVersion`, the three booleans and the receipt issue
time. WordPress records acceptance and registration timestamps. API tests do not
prove that a human read a rendered notice. A future participant interface needs
its own wording approval, accessibility checks and rendered end-to-end assurance.

The signed receipt is not encrypted: its opaque local account reference can be
decoded by its holder. It grants **registration only**, not approval, invitation
or voting. It expires within 60 seconds and cannot outlive the issue-time identity,
browser or WordPress challenge deadline. WordPress consumes it once. A logout
after issuance does not remotely revoke this offline receipt; later voting still
requires a current signed-in approved account, bound invitation and activation.
