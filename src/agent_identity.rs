//! Resolves the agent's stable identity, persisting a generated UUID to
//! `~/.monitor-agent/agent_id` so restarts don't collide under the default
//! `--agent-id` (previously the hardcoded string `"agent-001"`).

use std::path::PathBuf;

use tracing::warn;
use uuid::Uuid;

/// Resolve the agent's identity. If `cli_override` is set (explicit
/// `--agent-id`/env), it wins outright and nothing is read from or written
/// to disk. Otherwise, reuse the persisted UUID if one exists, or generate
/// and persist a new one. Filesystem errors degrade to an unpersisted,
/// freshly-generated UUID rather than failing startup.
pub fn resolve(cli_override: Option<String>) -> String {
    if let Some(id) = cli_override {
        return id;
    }

    let Some(path) = identity_path() else {
        warn!(
            "could not determine home directory; agent identity will not persist across restarts"
        );
        return Uuid::new_v4().to_string();
    };

    if let Ok(existing) = std::fs::read_to_string(&path) {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }

    let id = Uuid::new_v4().to_string();
    if let Some(parent) = path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        warn!(error = %e, path = %parent.display(), "failed to create agent identity directory; identity will not persist");
        return id;
    }
    if let Err(e) = std::fs::write(&path, &id) {
        warn!(error = %e, path = %path.display(), "failed to persist agent identity; will regenerate on next restart");
    }
    id
}

fn identity_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".monitor-agent").join("agent_id"))
}
