use rusqlite::{Connection, Result};

pub(super) fn apply(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS cluster_metadata (
             singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
             cluster_epoch INTEGER NOT NULL
         ) STRICT;
         INSERT OR IGNORE INTO cluster_metadata (singleton, cluster_epoch) VALUES (1, 1);
         CREATE TABLE IF NOT EXISTS recovery_audit (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             previous_epoch INTEGER NOT NULL,
             next_epoch INTEGER NOT NULL,
             reason TEXT NOT NULL,
             created_at INTEGER NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS enrollment_tokens (
             secret_hash BLOB PRIMARY KEY NOT NULL,
             expected_node TEXT NOT NULL,
             approved_endpoint TEXT NOT NULL,
             overlay_scope TEXT NOT NULL,
             expires_at INTEGER NOT NULL,
             consumed_at INTEGER
         ) STRICT;
         CREATE TABLE IF NOT EXISTS nodes (
             node_id TEXT PRIMARY KEY NOT NULL,
             public_key BLOB UNIQUE NOT NULL,
             endpoint TEXT UNIQUE NOT NULL,
             revoked_at INTEGER,
             revocation_reason TEXT
         ) STRICT;
         CREATE TABLE IF NOT EXISTS overlays (
             overlay_id TEXT PRIMARY KEY NOT NULL,
             cidr TEXT UNIQUE NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS node_subnets (
             overlay_id TEXT NOT NULL REFERENCES overlays(overlay_id),
             node_id TEXT NOT NULL REFERENCES nodes(node_id),
             cidr TEXT UNIQUE NOT NULL,
             PRIMARY KEY (overlay_id, node_id)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS desired_revisions (
             revision INTEGER PRIMARY KEY NOT NULL,
             overlay_id TEXT NOT NULL REFERENCES overlays(overlay_id),
             payload BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS desired_authorizations (
             revision INTEGER NOT NULL REFERENCES desired_revisions(revision) ON DELETE CASCADE,
             node_id TEXT NOT NULL REFERENCES nodes(node_id),
             bundle BLOB NOT NULL,
             PRIMARY KEY (revision, node_id)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS acknowledgements (
             node_id TEXT NOT NULL REFERENCES nodes(node_id),
             revision INTEGER NOT NULL REFERENCES desired_revisions(revision),
             PRIMARY KEY (node_id, revision)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS node_observations (
             node_id TEXT PRIMARY KEY NOT NULL REFERENCES nodes(node_id),
             last_seen_unix INTEGER NOT NULL,
             version TEXT NOT NULL,
             health TEXT NOT NULL,
             doctor_summary TEXT NOT NULL,
             containers_json TEXT NOT NULL,
             acknowledged_revision INTEGER NOT NULL
         ) STRICT;",
    )
}
