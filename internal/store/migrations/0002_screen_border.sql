-- File purpose: Adds screen borders while preserving pending deliveries and receipts.
-- Copyright (c) 2026 RealisLux
-- SPDX-License-Identifier: MIT
-- Project: https://github.com/RealisLux/NeoDSE

CREATE TABLE command_receipts_new(
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('received','accepted','completed','failed','expired','unsupported')),
    operation TEXT NOT NULL CHECK(operation IN ('desired_state','display','display_volume','sound','serial','banner','border','reload','restart','reboot','shutdown')),
    error TEXT NOT NULL DEFAULT '' CHECK(length(error) <= 1024 AND instr(error, char(0)) = 0),
    details TEXT NOT NULL DEFAULT '' CHECK(length(details) <= 768 AND instr(details, char(0)) = 0),
    value TEXT NOT NULL DEFAULT '' CHECK(length(value) <= 32 AND instr(value, char(0)) = 0),
    reported_at TEXT NOT NULL,
    FOREIGN KEY(event_id, agent_id) REFERENCES event_targets(event_id, agent_id) ON DELETE CASCADE
) STRICT;

INSERT INTO command_receipts_new SELECT * FROM command_receipts;
DROP TABLE command_receipts;
ALTER TABLE command_receipts_new RENAME TO command_receipts;
CREATE INDEX command_receipts_event ON command_receipts(event_id, id);

CREATE TABLE pending_deliveries_new(
    event_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    command_type TEXT NOT NULL CHECK(command_type IN ('display','display_volume','sound','serial','banner','border','reload','restart','reboot','shutdown')),
    command_json TEXT NOT NULL CHECK(
        length(CAST(command_json AS BLOB)) BETWEEN 2 AND 32768
        AND json_valid(command_json)
        AND json_type(command_json) = 'object'
        AND json_extract(command_json, '$.type') = command_type
    ),
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(event_id, agent_id),
    FOREIGN KEY(event_id, agent_id) REFERENCES event_targets(event_id, agent_id) ON DELETE CASCADE
) STRICT;

INSERT INTO pending_deliveries_new SELECT * FROM pending_deliveries;
DROP TABLE pending_deliveries;
ALTER TABLE pending_deliveries_new RENAME TO pending_deliveries;
CREATE INDEX pending_deliveries_agent_created ON pending_deliveries(agent_id, created_at, event_id);
