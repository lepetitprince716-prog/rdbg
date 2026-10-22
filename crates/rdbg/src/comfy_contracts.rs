//! Strict, versioned observation contracts for the `rdbg comfy` actions.
//!
//! Same rules as `contracts.rs`: every struct rejects unknown keys, and every key is
//! required, including the ones whose value may be `null`.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::comfy::ActionId;

fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

/// Every reason string the remote script can report. Reasons are stable identifiers.
pub(crate) const KNOWN_REASONS: &[&str] = &[
    "comfy_unreachable",
    "delete_failed",
    "launcher_conflict",
    "launcher_scan_failed",
    "listener_query_failed",
    "not_administrator",
    "not_ready_timeout",
    "port_in_use",
    "port_not_listening",
    "port_still_busy",
    "python_missing",
    "restart_failed",
    "rogue_listener",
    "rollback_delete_failed",
    "rollback_stop_failed",
    "root_main_py_missing",
    "service_exists",
    "service_missing",
    "service_not_running",
    "service_not_shawl_managed",
    "service_query_failed",
    "set_start_type_failed",
    "shawl_add_failed",
    "shawl_hash_mismatch",
    "shawl_hash_unreadable",
    "shawl_missing",
    "start_failed",
    "stop_failed",
    "stop_timeout",
    "version_mismatch",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ActionOutcome {
    Done,
    Refused,
    Failed,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceView {
    name: String,
    present: bool,
    status: String,
    pid: i64,
    #[serde(deserialize_with = "nullable")]
    start_type: Option<String>,
    #[serde(deserialize_with = "nullable")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerView {
    port: i64,
    listening: bool,
    owner_pids: Vec<i64>,
    #[serde(deserialize_with = "nullable")]
    all_owners_service_bound: Option<bool>,
    #[serde(deserialize_with = "nullable")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveView {
    reachable: bool,
    base_uri: String,
    #[serde(deserialize_with = "nullable")]
    version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    expected_version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    version_matches: Option<bool>,
    #[serde(deserialize_with = "nullable")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ConflictKind {
    Service,
    ScheduledTask,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LauncherConflict {
    kind: ConflictKind,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StartType {
    Auto,
    Manual,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StatusObservation {
    schema: String,
    outcome: ActionOutcome,
    changed: bool,
    reasons: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    service: Option<ServiceView>,
    listener: ListenerView,
    live: LiveView,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RestartObservation {
    schema: String,
    outcome: ActionOutcome,
    changed: bool,
    reasons: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    service: Option<ServiceView>,
    listener: ListenerView,
    live: LiveView,
    ready: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallObservation {
    schema: String,
    outcome: ActionOutcome,
    changed: bool,
    reasons: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    service: Option<ServiceView>,
    listener: ListenerView,
    live: LiveView,
    ready: bool,
    rolled_back: bool,
    start_type: StartType,
    #[serde(deserialize_with = "nullable")]
    log_dir: Option<String>,
    conflicts: Vec<LauncherConflict>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UninstallObservation {
    schema: String,
    outcome: ActionOutcome,
    changed: bool,
    reasons: Vec<String>,
    #[serde(deserialize_with = "nullable")]
    service: Option<ServiceView>,
    listener: ListenerView,
    live: LiveView,
    removed: bool,
}

/// The fields every action observation shares, for the consistency checks.
trait Common {
    fn schema(&self) -> &str;
    fn outcome(&self) -> ActionOutcome;
    fn changed(&self) -> bool;
    fn reasons(&self) -> &[String];
    /// Action-specific consistency between the outcome and the extra fields.
    fn check_extra(&self) -> Result<(), String>;
}

macro_rules! common {
    ($($kind:ty),* $(,)?) => {
        $(impl Common for $kind {
            fn schema(&self) -> &str {
                &self.schema
            }
            fn outcome(&self) -> ActionOutcome {
                self.outcome
            }
            fn changed(&self) -> bool {
                self.changed
            }
            fn reasons(&self) -> &[String] {
                &self.reasons
            }
            fn check_extra(&self) -> Result<(), String> {
                Extra::check(self)
            }
        })*
    };
}

common!(
    StatusObservation,
    RestartObservation,
    InstallObservation,
    UninstallObservation,
);

trait Extra {
    fn check(&self) -> Result<(), String>;
}

impl Extra for StatusObservation {
    fn check(&self) -> Result<(), String> {
        if self.outcome != ActionOutcome::Done || self.changed {
            return Err("status must be outcome done with changed false".to_owned());
        }
        Ok(())
    }
}

impl Extra for RestartObservation {
    fn check(&self) -> Result<(), String> {
        if self.ready != (self.outcome == ActionOutcome::Done) {
            return Err("restart ready must be true exactly when the outcome is done".to_owned());
        }
        Ok(())
    }
}

impl Extra for InstallObservation {
    fn check(&self) -> Result<(), String> {
        if self.ready != (self.outcome == ActionOutcome::Done) {
            return Err("install ready must be true exactly when the outcome is done".to_owned());
        }
        if self.rolled_back && self.outcome != ActionOutcome::Failed {
            return Err("install rolled_back requires outcome failed".to_owned());
        }
        Ok(())
    }
}

impl Extra for UninstallObservation {
    fn check(&self) -> Result<(), String> {
        if self.removed != (self.outcome == ActionOutcome::Done) {
            return Err(
                "uninstall removed must be true exactly when the outcome is done".to_owned(),
            );
        }
        Ok(())
    }
}

fn parse_as<T>(text: &str, action: ActionId) -> Result<(Value, ActionOutcome), String>
where
    T: for<'de> Deserialize<'de> + Serialize + Common,
{
    let parsed: T = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let expected = action.schema();
    if parsed.schema() != expected {
        return Err(format!("schema must be {expected}"));
    }
    if let Some(reason) = parsed
        .reasons()
        .iter()
        .find(|reason| !KNOWN_REASONS.contains(&reason.as_str()))
    {
        return Err(format!("unknown reason '{reason}'"));
    }
    match parsed.outcome() {
        ActionOutcome::Refused if parsed.changed() => {
            return Err("a refused action must report changed false".to_owned());
        }
        ActionOutcome::Refused | ActionOutcome::Failed if parsed.reasons().is_empty() => {
            return Err("a refused or failed action must report at least one reason".to_owned());
        }
        _ => {}
    }
    parsed.check_extra()?;
    let outcome = parsed.outcome();
    let value = serde_json::to_value(&parsed).map_err(|error| error.to_string())?;
    Ok((value, outcome))
}

/// Validate one action's stdout against its strict contract and return the
/// normalized observation and its outcome, or the reason it was rejected.
pub(crate) fn validate_observation(
    text: &str,
    action: ActionId,
) -> Result<(Value, ActionOutcome), String> {
    match action {
        ActionId::Status => parse_as::<StatusObservation>(text, action),
        ActionId::Restart => parse_as::<RestartObservation>(text, action),
        ActionId::InstallService => parse_as::<InstallObservation>(text, action),
        ActionId::UninstallService => parse_as::<UninstallObservation>(text, action),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    fn base(action: ActionId) -> Value {
        json!({
            "schema": action.schema(),
            "outcome": "done",
            "changed": action != ActionId::Status,
            "reasons": [],
            "service": {
                "name": "Svc", "present": true, "status": "Running", "pid": 10,
                "start_type": "Auto", "error": null
            },
            "listener": {
                "port": 8188, "listening": true, "owner_pids": [100],
                "all_owners_service_bound": true, "error": null
            },
            "live": {
                "reachable": true, "base_uri": "http://127.0.0.1:8188", "version": "1.0.0",
                "expected_version": "1.0.0", "version_matches": true, "error": null
            }
        })
    }

    pub(crate) fn sample(action: ActionId) -> Value {
        let mut value = base(action);
        let map = value.as_object_mut().unwrap();
        match action {
            ActionId::Status => {}
            ActionId::Restart => {
                map.insert("ready".to_owned(), json!(true));
            }
            ActionId::InstallService => {
                map.insert("ready".to_owned(), json!(true));
                map.insert("rolled_back".to_owned(), json!(false));
                map.insert("start_type".to_owned(), json!("auto"));
                map.insert("log_dir".to_owned(), json!("C:\\tools"));
                map.insert(
                    "conflicts".to_owned(),
                    json!([{"kind": "scheduled_task", "name": "\\Start ComfyUI"}]),
                );
            }
            ActionId::UninstallService => {
                map.insert("removed".to_owned(), json!(true));
            }
        }
        value
    }

    fn check(value: &Value, action: ActionId) -> Result<(Value, ActionOutcome), String> {
        validate_observation(&value.to_string(), action)
    }

    fn object_pointers(value: &Value, pointer: String, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                out.push(pointer.clone());
                for (key, child) in map {
                    object_pointers(child, format!("{pointer}/{key}"), out);
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    object_pointers(child, format!("{pointer}/{index}"), out);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn every_action_sample_passes_and_round_trips() {
        for action in ActionId::ALL {
            let value = sample(action);
            let (normalized, outcome) = check(&value, action)
                .unwrap_or_else(|error| panic!("{} sample rejected: {error}", action.id()));
            assert_eq!(normalized, value);
            assert_eq!(outcome, ActionOutcome::Done);
        }
    }

    #[test]
    fn extra_key_fails_at_every_object_level() {
        for action in ActionId::ALL {
            let value = sample(action);
            let mut pointers = Vec::new();
            object_pointers(&value, String::new(), &mut pointers);
            for pointer in pointers {
                let mut mutated = value.clone();
                mutated
                    .pointer_mut(&pointer)
                    .unwrap()
                    .as_object_mut()
                    .unwrap()
                    .insert("unexpected_extra".to_owned(), json!(1));
                assert!(
                    check(&mutated, action).is_err(),
                    "{} accepted an extra key at '{pointer}'",
                    action.id()
                );
            }
        }
    }

    #[test]
    fn deleting_any_required_key_fails() {
        for action in ActionId::ALL {
            let value = sample(action);
            let mut pointers = Vec::new();
            object_pointers(&value, String::new(), &mut pointers);
            let mut checked = 0;
            for pointer in pointers {
                let keys: Vec<String> = value
                    .pointer(&pointer)
                    .unwrap()
                    .as_object()
                    .unwrap()
                    .keys()
                    .cloned()
                    .collect();
                for key in keys {
                    let mut mutated = value.clone();
                    mutated
                        .pointer_mut(&pointer)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(&key);
                    assert!(
                        check(&mutated, action).is_err(),
                        "{} accepted a missing '{pointer}/{key}'",
                        action.id()
                    );
                    checked += 1;
                }
            }
            assert!(checked > 20, "{} checked only {checked} keys", action.id());
        }
    }

    #[test]
    fn nullable_keys_accept_null() {
        let mut value = sample(ActionId::Status);
        value["service"] = Value::Null;
        value["listener"]["all_owners_service_bound"] = Value::Null;
        for key in ["version", "expected_version", "version_matches"] {
            value["live"][key] = Value::Null;
        }
        assert!(check(&value, ActionId::Status).is_ok());
    }

    #[test]
    fn strict_types_and_reasons_reject_bad_values() {
        let cases: &[(ActionId, &str, Value)] = &[
            (ActionId::Status, "/outcome", json!("ok")),
            (ActionId::Status, "/changed", json!("no")),
            (ActionId::Status, "/reasons", json!(["Not Snake"])),
            (ActionId::Status, "/reasons", json!(["made_up_reason"])),
            (ActionId::Status, "/listener/port", json!("8188")),
            (ActionId::Status, "/service/pid", json!(1.5)),
            (ActionId::InstallService, "/start_type", json!("delayed")),
            (ActionId::InstallService, "/conflicts/0/kind", json!("task")),
        ];
        for (action, pointer, replacement) in cases {
            let mut value = sample(*action);
            *value.pointer_mut(pointer).unwrap() = replacement.clone();
            assert!(
                check(&value, *action).is_err(),
                "{} accepted {pointer} = {replacement}",
                action.id()
            );
        }
    }

    #[test]
    fn outcome_consistency_is_enforced() {
        let mut refused = sample(ActionId::Restart);
        refused["outcome"] = json!("refused");
        refused["ready"] = json!(false);
        refused["changed"] = json!(false);
        assert!(check(&refused, ActionId::Restart).is_err(), "no reason");
        refused["reasons"] = json!(["rogue_listener"]);
        let (_, outcome) = check(&refused, ActionId::Restart).unwrap();
        assert_eq!(outcome, ActionOutcome::Refused);
        refused["changed"] = json!(true);
        assert!(
            check(&refused, ActionId::Restart).is_err(),
            "refused+changed"
        );

        let mut status = sample(ActionId::Status);
        status["outcome"] = json!("failed");
        status["reasons"] = json!(["comfy_unreachable"]);
        assert!(check(&status, ActionId::Status).is_err());

        let mut install = sample(ActionId::InstallService);
        install["ready"] = json!(false);
        assert!(check(&install, ActionId::InstallService).is_err());

        let mut uninstall = sample(ActionId::UninstallService);
        uninstall["removed"] = json!(false);
        assert!(check(&uninstall, ActionId::UninstallService).is_err());
    }

    #[test]
    fn wrong_or_foreign_schema_fails() {
        let mut value = sample(ActionId::Status);
        value["schema"] = json!("rdbg.comfy.status.v2");
        assert!(check(&value, ActionId::Status).is_err());
        let restart = sample(ActionId::Restart);
        assert!(check(&restart, ActionId::UninstallService).is_err());
    }

    #[test]
    fn every_reason_in_the_script_is_known_and_snake_case() {
        let script = crate::comfy::SCRIPT_BODY;
        let mut found = std::collections::BTreeSet::new();
        for (marker, quote) in [("Add-Reason '", '\''), ("$found += '", '\'')] {
            for piece in script.split(marker).skip(1) {
                found.insert(piece.split(quote).next().unwrap().to_owned());
            }
        }
        assert!(found.len() > 20, "{found:?}");
        for reason in &found {
            assert!(KNOWN_REASONS.contains(&reason.as_str()), "{reason}");
        }
        for reason in KNOWN_REASONS {
            assert!(found.contains(*reason), "unused reason {reason}");
            assert!(
                reason
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_')
            );
        }
    }
}
