use crate::LOG_DRAIN;

use serde::{Deserialize, Serialize};
use slog::info;
use std::collections::HashMap;

// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    pub excluded_namespaces: Vec<String>,
    pub excluded_pod_labels: HashMap<String, String>,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");


        // TODO: perform settings validation if applies
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings() -> Result<(), ()> {
        let excluded_namespaces = vec!["foo".to_string()];

        let excluded_pod_labels = HashMap::from([
            ("istioException".to_string(), "enabled".to_string()),
        ]);

        let settings = Settings {
            excluded_namespaces: excluded_namespaces,
            excluded_pod_labels: excluded_pod_labels,
        };

        assert!(settings.validate().is_ok());
        Ok(())
    }
}
