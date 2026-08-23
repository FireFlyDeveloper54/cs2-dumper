//! Emitter for the game-events registry (gameevents.json).

use serde_json::json;

use crate::analysis::gameevents::GameEvent;

pub fn render_json(events: &[GameEvent], build: Option<u32>) -> String {
    let rows: Vec<_> = events
        .iter()
        .map(|e| {
            json!({
                "name": e.name,
                "id": e.id,
                "local": e.local,
                "fields": e.fields.iter().map(|f| json!({
                    "name": f.name,
                    "type": f.type_name,
                    "description": f.description,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    serde_json::to_string_pretty(&json!({
        "build_number": build,
        "event_count": events.len(),
        "events": rows,
    }))
    .unwrap_or_else(|_| "{}".into())
}
