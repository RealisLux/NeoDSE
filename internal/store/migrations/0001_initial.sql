CREATE TABLE agent_credentials(
    agent_id TEXT PRIMARY KEY CHECK(length(agent_id) BETWEEN 1 AND 128),
    psk TEXT NOT NULL CHECK(length(psk) = 64),
    tunnel_address TEXT NOT NULL CHECK(length(tunnel_address) BETWEEN 7 AND 15),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE TABLE desired_states(
    agent_id TEXT PRIMARY KEY,
    generation TEXT NOT NULL CHECK(length(generation) = 32),
    revision INTEGER NOT NULL CHECK(revision > 0),
    content_mode TEXT NOT NULL CHECK(content_mode IN ('default', 'playlist')),
    interval_seconds INTEGER NOT NULL DEFAULT 0 CHECK(interval_seconds BETWEEN 0 AND 86400),
    start_at INTEGER NOT NULL DEFAULT 0 CHECK(start_at BETWEEN 0 AND 4102444800),
    updated_at TEXT NOT NULL,
    FOREIGN KEY(agent_id) REFERENCES agent_credentials(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE desired_playlist_items(
    agent_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0 AND position < 6),
    url TEXT NOT NULL CHECK(length(url) BETWEEN 1 AND 8192),
    PRIMARY KEY(agent_id, position),
    FOREIGN KEY(agent_id) REFERENCES desired_states(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE desired_proxy_items(
    agent_id TEXT NOT NULL,
    position INTEGER NOT NULL CHECK(position >= 0 AND position < 128),
    url TEXT NOT NULL CHECK(length(url) BETWEEN 1 AND 8192),
    PRIMARY KEY(agent_id, position),
    FOREIGN KEY(agent_id) REFERENCES desired_states(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE proxy_policies(
    agent_id TEXT NOT NULL,
    target TEXT NOT NULL,
    PRIMARY KEY(agent_id, target),
    FOREIGN KEY(agent_id) REFERENCES agent_credentials(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE service_accounts(
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
    name TEXT NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 128),
    description TEXT NOT NULL DEFAULT '' CHECK(length(description) <= 1024),
    all_agents INTEGER NOT NULL DEFAULT 0 CHECK(all_agents IN (0, 1)),
    token_id TEXT NOT NULL UNIQUE CHECK(length(token_id) BETWEEN 1 AND 128),
    token_hash BLOB NOT NULL CHECK(length(token_hash) = 32),
    expires_at TEXT,
    disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_used_at TEXT
) STRICT;

CREATE TABLE service_account_roles(
    service_account_id TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('viewer','content_manager','alert_io_operator','cec_manager','system_operator','administrator')),
    PRIMARY KEY(service_account_id, role),
    FOREIGN KEY(service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE
) STRICT;

CREATE TABLE service_account_agents(
    service_account_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    PRIMARY KEY(service_account_id, agent_id),
    FOREIGN KEY(service_account_id) REFERENCES service_accounts(id) ON DELETE CASCADE,
    FOREIGN KEY(agent_id) REFERENCES agent_credentials(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE schedules(
    id TEXT PRIMARY KEY CHECK(length(id) BETWEEN 1 AND 128),
    agent_id TEXT NOT NULL UNIQUE,
    days TEXT NOT NULL CHECK(length(days) BETWEEN 1 AND 128),
    power_on TEXT NOT NULL,
    power_off TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    reminder_enabled INTEGER NOT NULL CHECK(reminder_enabled IN (0, 1)),
    last_on_occurrence TEXT,
    last_off_occurrence TEXT,
    last_warning_occurrence TEXT,
    FOREIGN KEY(agent_id) REFERENCES agent_credentials(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE agent_status(
    agent_id TEXT PRIMARY KEY,
    friendly_name TEXT NOT NULL DEFAULT '' CHECK(length(friendly_name) <= 32 AND instr(friendly_name, char(0)) = 0),
    protocol INTEGER NOT NULL,
    hostname TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    uptime_seconds INTEGER NOT NULL,
    last_event_id TEXT NOT NULL DEFAULT '',
    cec_enabled INTEGER NOT NULL DEFAULT 0 CHECK(cec_enabled IN (0,1)),
    cec_power_status TEXT NOT NULL DEFAULT 'unknown',
    cec_output TEXT NOT NULL DEFAULT '' CHECK(length(cec_output) <= 768 AND instr(cec_output, char(0)) = 0),
    cec_checked_at TEXT NOT NULL DEFAULT '',
    reported_at TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(agent_id) REFERENCES agent_credentials(agent_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE command_events(
    event_id TEXT PRIMARY KEY CHECK(length(event_id) BETWEEN 1 AND 128),
    source TEXT NOT NULL CHECK(length(source) BETWEEN 1 AND 128),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;

CREATE INDEX command_events_retention ON command_events(created_at, event_id);

CREATE TABLE event_targets(
    event_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    delivery_status TEXT NOT NULL DEFAULT 'queued' CHECK(delivery_status IN ('queued','uncertain','received','accepted','completed','failed','expired','unsupported','rejected')),
    delivery_reason TEXT NOT NULL DEFAULT '' CHECK(length(delivery_reason)<=128),
    desired_generation TEXT CHECK(desired_generation IS NULL OR length(desired_generation) = 32),
    desired_revision INTEGER CHECK(desired_revision IS NULL OR desired_revision > 0),
    PRIMARY KEY(event_id, agent_id),
    FOREIGN KEY(event_id) REFERENCES command_events(event_id) ON DELETE CASCADE,
    FOREIGN KEY(agent_id) REFERENCES agent_credentials(agent_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX event_targets_unresolved_desired ON event_targets(agent_id, desired_revision)
    WHERE desired_revision IS NOT NULL AND delivery_status IN ('queued','uncertain','received');

CREATE TABLE command_receipts(
    id INTEGER PRIMARY KEY,
    event_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('received','accepted','completed','failed','expired','unsupported')),
    operation TEXT NOT NULL CHECK(operation IN ('desired_state','display','display_volume','sound','serial','banner','reload','restart','reboot','shutdown')),
    error TEXT NOT NULL DEFAULT '' CHECK(length(error) <= 1024 AND instr(error, char(0)) = 0),
    details TEXT NOT NULL DEFAULT '' CHECK(length(details) <= 768 AND instr(details, char(0)) = 0),
    value TEXT NOT NULL DEFAULT '' CHECK(length(value) <= 32 AND instr(value, char(0)) = 0),
    reported_at TEXT NOT NULL,
    FOREIGN KEY(event_id, agent_id) REFERENCES event_targets(event_id, agent_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX command_receipts_event ON command_receipts(event_id, id);

CREATE TABLE pending_deliveries(
    event_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    command_type TEXT NOT NULL CHECK(command_type IN ('display','display_volume','sound','serial','banner','reload','restart','reboot','shutdown')),
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

CREATE INDEX pending_deliveries_agent_created ON pending_deliveries(agent_id, created_at, event_id);
