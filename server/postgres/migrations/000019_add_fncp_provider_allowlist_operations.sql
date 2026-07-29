-- First Nations Community Pulse provider-operation ordering.
--
-- The tombstone is deliberately separate from xid_whitelist. A version-2
-- removal must survive after the allowlist row is deleted so a delayed
-- version-1 upsert cannot recreate access.

CREATE TABLE fncp_provider_allowlist_operations (
  zid INTEGER NOT NULL REFERENCES conversations(zid) ON DELETE CASCADE,
  xid TEXT NOT NULL,
  operation_version SMALLINT NOT NULL,
  desired_present BOOLEAN NOT NULL,
  PRIMARY KEY (zid, xid),
  CONSTRAINT fncp_provider_allowlist_operation_version_check
    CHECK (operation_version IN (1, 2)),
  CONSTRAINT fncp_provider_allowlist_operation_state_check
    CHECK (
      (operation_version = 1 AND desired_present IS TRUE)
      OR (operation_version = 2 AND desired_present IS FALSE)
    )
);

CREATE INDEX fncp_provider_allowlist_operations_xid_idx
  ON fncp_provider_allowlist_operations (xid);

COMMENT ON TABLE fncp_provider_allowlist_operations IS
  'FNCP monotonic provider allowlist state; version 2 is a removal tombstone.';
