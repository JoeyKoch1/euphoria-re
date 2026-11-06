use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

// User edits that live beside the analysis result rather than inside it.
#[derive(Default, Serialize, Deserialize)]
pub struct Workspace {
    #[serde(default)]
    pub names: BTreeMap<u64, String>,
    #[serde(default)]
    pub comments: BTreeMap<u64, String>,
}

impl Workspace {
    pub fn from_extras(extras: &Value) -> Self {
        extras
            .get("workspace")
            .and_then(|saved| serde_json::from_value(saved.clone()).ok())
            .unwrap_or_default()
    }

    pub fn merge(self, extras: Value) -> Value {
        let mut extras = match extras {
            Value::Object(map) => Value::Object(map),
            _ => Value::Object(serde_json::Map::new()),
        };
        if let Value::Object(map) = &mut extras {
            map.insert(
                "workspace".into(),
                serde_json::to_value(self).unwrap_or(Value::Null),
            );
        }
        extras
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_names_and_comments_through_extras() {
        let extras = serde_json::json!({ "hosts": [] });
        let mut workspace = Workspace::from_extras(&extras);
        workspace.names.insert(0x401000, "decrypt".into());
        workspace
            .comments
            .insert(0x401004, "checks the header".into());

        let saved = workspace.merge(extras);
        assert_eq!(saved["hosts"], serde_json::json!([]));

        let restored = Workspace::from_extras(&saved);
        assert_eq!(
            restored.names.get(&0x401000).map(String::as_str),
            Some("decrypt")
        );
        assert_eq!(
            restored.comments.get(&0x401004).map(String::as_str),
            Some("checks the header")
        );
    }

    #[test]
    fn ignores_missing_or_damaged_workspace_data() {
        assert!(Workspace::from_extras(&Value::Null).names.is_empty());
        assert!(
            Workspace::from_extras(&serde_json::json!({ "workspace": "nope" }))
                .names
                .is_empty()
        );
        let merged = Workspace::default().merge(Value::Null);
        assert_eq!(
            merged["workspace"],
            serde_json::json!({ "names": {}, "comments": {} })
        );
    }
}
