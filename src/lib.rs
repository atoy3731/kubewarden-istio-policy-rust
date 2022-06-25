use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;
use std::collections::BTreeMap;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{info, o, warn, Logger};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "sample-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn check_namespace(settings: settings::Settings, obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<apicore::Namespace>(obj) {
        Ok(namespace) => {
            let namespace_name: String = namespace.metadata.name.unwrap();

            for excluded_namespace in settings.excluded_namespaces {
                if namespace_name == excluded_namespace {
                    return kubewarden::accept_request();
                }
            }

            let namespace_labels: BTreeMap<String, String> = namespace.metadata.labels.unwrap();

            for (k, v) in namespace_labels {
                if k == "istio-injection" && v == "enabled" {
                    return kubewarden::accept_request();
                }
            }

            kubewarden::reject_request(
                Some(format!(
                    "Namespace '{}' is not istio enabled.",
                    namespace_name
                )),
                None,
                None,
                None,
            )
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn check_pod(settings: settings::Settings, obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<apicore::Pod>(obj) {
        Ok(pod) => {
            let pod_name: String = pod.metadata.name.unwrap();
            let pod_annotations: BTreeMap<String, String> = pod.metadata.annotations.unwrap();

            if pod_annotations.len() > 0 {
                let pod_labels: BTreeMap<String, String> = pod.metadata.labels.unwrap();

                for (k, v) in settings.excluded_pod_labels {
                    if pod_labels.contains_key(&k) {
                        let unwrapped_val = pod_labels.get(&k).unwrap();
                        if &v == unwrapped_val {
                            return kubewarden::accept_request();
                        }
                    }
                }

                if pod_annotations.contains_key("sidecar.istio.io/inject") {
                    info!(LOG_DRAIN, "Pod Name: {}", pod_name);
                    //     let unwrapped_value = pod_annotations.get("sidecar.istio.io/inject").unwrap();
                    //     if unwrapped_value == "false" {
                    //         return kubewarden::reject_request(
                    //             Some(format!("Pod '{}' is not istio enabled.", pod_name)),
                    //             None,
                    //             None,
                    //             None,
                    //         );
                    //     }
                }

                kubewarden::accept_request()
            } else {
                kubewarden::accept_request()
            }
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");

    let kind: String = validation_request.request.kind.kind;

    return match kind.as_ref() {
        "Namespace" => check_namespace(
            validation_request.settings,
            validation_request.request.object,
        ),
        "Pod" => check_pod(
            validation_request.settings,
            validation_request.request.object,
        ),
        _ => kubewarden::accept_request(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::test::Testcase;
    use std::collections::HashMap;

    #[test]
    fn deny_request_with_istio_disabled_namespace() -> Result<(), ()> {
        let excluded_namespaces = vec!["bar".to_string()];

        let excluded_pod_labels =
            HashMap::from([("istioException".to_string(), "enabled".to_string())]);

        let request_file = "test_data/namespace-disabled.json";
        let tc = Testcase {
            name: String::from("Namespace Creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                excluded_namespaces: excluded_namespaces,
                excluded_pod_labels: excluded_pod_labels,
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_request_with_excluded_namespace() -> Result<(), ()> {
        let excluded_namespaces = vec!["foo".to_string()];

        let excluded_pod_labels =
            HashMap::from([("istioException".to_string(), "enabled".to_string())]);

        let request_file = "test_data/namespace-disabled.json";
        let tc = Testcase {
            name: String::from("Namespace Creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                excluded_namespaces: excluded_namespaces,
                excluded_pod_labels: excluded_pod_labels,
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    // #[test]
    // fn deny_request_with_istio_disabled_pod() -> Result<(), ()> {
    //     let excluded_namespaces = vec!["foo".to_string()];

    //     let excluded_pod_labels =
    //         HashMap::from([("istioException".to_string(), "disabled".to_string())]);

    //     let request_file = "test_data/pod-disabled.json";
    //     let tc = Testcase {
    //         name: String::from("Deny - Pod Istio Disabled"),
    //         fixture_file: String::from(request_file),
    //         expected_validation_result: false,
    //         settings: Settings {
    //             excluded_namespaces: excluded_namespaces,
    //             excluded_pod_labels: excluded_pod_labels,
    //         },
    //     };

    //     let res = tc.eval(validate).unwrap();
    //     assert!(
    //         res.mutated_object.is_none(),
    //         "Something mutated with test case: {}",
    //         tc.name,
    //     );

    //     Ok(())
    // }

    #[test]
    fn accept_request_with_istio_enabled_pod() -> Result<(), ()> {
        let excluded_namespaces = vec!["foo".to_string()];

        let excluded_pod_labels =
            HashMap::from([("istioException".to_string(), "disabled".to_string())]);

        let request_file = "test_data/pod-enabled.json";
        let tc = Testcase {
            name: String::from("Pod Creation"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                excluded_namespaces: excluded_namespaces,
                excluded_pod_labels: excluded_pod_labels,
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
