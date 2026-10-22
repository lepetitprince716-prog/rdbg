//! Strict, versioned observation contracts for the fixed `rdbg doctor` probes.
//!
//! Every struct rejects unknown keys. A field whose value may be `null` is still
//! required to be present: `Option<T>` fields use [`nullable`], which makes serde
//! report a missing key instead of silently defaulting to `None`. The only key
//! that may be omitted is `NetworkAdapter::description`.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};

use crate::doctor::ProbeId;

/// Deserialize a required key whose value may be `null`.
///
/// serde treats a missing `Option<T>` field as `None` unless the field has a
/// `deserialize_with` function, in which case the key becomes mandatory.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportObservation {
    schema: String,
    healthy: bool,
    computer_name: String,
    powershell_version: String,
    powershell_edition: String,
    remote_time_utc: String,
    encoding_sentinel: String,
    apostrophe_sentinel: String,
    dollar_sentinel: String,
    json_literal_ok: bool,
    multiline_ok: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceObservation {
    name: String,
    status: String,
    present: bool,
    running: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OverviewObservation {
    schema: String,
    healthy: bool,
    computer_name: String,
    powershell_version: String,
    os_caption: String,
    os_version: String,
    os_build: String,
    last_boot_utc: String,
    uptime_seconds: Number,
    memory_total_mb: Number,
    memory_free_mb: Number,
    cpu_name: String,
    logical_processors: i64,
    services: Vec<ServiceObservation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkAdapterObservation {
    alias: String,
    #[serde(default)]
    description: Option<String>,
    ipv4: Vec<String>,
    gateways: Vec<String>,
    dns: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NetworkObservation {
    schema: String,
    healthy: bool,
    computer_name: String,
    adapters: Vec<NetworkAdapterObservation>,
    ssh_port_22: bool,
    comfyui_port: i64,
    comfyui_listening: bool,
    #[serde(deserialize_with = "nullable")]
    collection_error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComfyDeviceObservation {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    vram_total_mb: Number,
    vram_free_mb: Number,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ComfyUiObservation {
    schema: String,
    healthy: bool,
    reachable: bool,
    base_uri: String,
    #[serde(deserialize_with = "nullable")]
    version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    expected_version: Option<String>,
    version_matches: bool,
    #[serde(deserialize_with = "nullable")]
    queue_running: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    queue_pending: Option<i64>,
    devices: Vec<ComfyDeviceObservation>,
    #[serde(deserialize_with = "nullable")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessLineageObservation {
    depth: i64,
    pid: i64,
    #[serde(deserialize_with = "nullable")]
    name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    executable: Option<String>,
    #[serde(deserialize_with = "nullable")]
    parent_pid: Option<i64>,
    found: bool,
    #[serde(deserialize_with = "nullable")]
    query_error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerProcessObservation {
    pid: i64,
    #[serde(deserialize_with = "nullable")]
    name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    executable: Option<String>,
    #[serde(deserialize_with = "nullable")]
    parent_pid: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    service_bound: Option<bool>,
    #[serde(deserialize_with = "nullable")]
    canonical_python_in_lineage: Option<bool>,
    lineage: Vec<ProcessLineageObservation>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerServiceObservation {
    name: String,
    status: String,
    present: bool,
    process_id: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ListenerVerdict {
    ListenerPresent,
    Missing,
    Canonical,
    Rogue,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListenerObservation {
    schema: String,
    healthy: bool,
    port: i64,
    listening: bool,
    verdict: ListenerVerdict,
    service_pid: i64,
    all_owners_service_bound: bool,
    all_owners_canonical_python: bool,
    processes: Vec<ListenerProcessObservation>,
    #[serde(deserialize_with = "nullable")]
    expected_service: Option<String>,
    #[serde(deserialize_with = "nullable")]
    canonical_python: Option<String>,
    #[serde(deserialize_with = "nullable")]
    service: Option<ListenerServiceObservation>,
    #[serde(deserialize_with = "nullable")]
    collection_error: Option<String>,
    #[serde(deserialize_with = "nullable")]
    service_collection_error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GpuDeviceObservation {
    index: i64,
    name: String,
    #[serde(deserialize_with = "nullable")]
    driver_version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    memory_total_mb: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    memory_used_mb: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    memory_free_mb: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    utilization_gpu_pct: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    utilization_memory_pct: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    temperature_c: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    power_draw_w: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    power_limit_w: Option<f64>,
    #[serde(deserialize_with = "nullable")]
    pstate: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GpuProcessObservation {
    pid: i64,
    process_name: String,
    #[serde(deserialize_with = "nullable")]
    used_memory_mb: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GpuObservation {
    schema: String,
    healthy: bool,
    available: bool,
    collected_at_utc: String,
    devices: Vec<GpuDeviceObservation>,
    compute_processes: Vec<GpuProcessObservation>,
    #[serde(deserialize_with = "nullable")]
    warning: Option<String>,
    #[serde(deserialize_with = "nullable")]
    error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotGpuObservation {
    name: String,
    #[serde(deserialize_with = "nullable")]
    vendor: Option<String>,
    #[serde(deserialize_with = "nullable")]
    driver: Option<String>,
    #[serde(rename = "type", deserialize_with = "nullable")]
    kind: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotDiskObservation {
    #[serde(deserialize_with = "nullable")]
    filesystem: Option<String>,
    #[serde(deserialize_with = "nullable")]
    total_mb: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    used_mb: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    available_mb: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum SnapshotCollector {
    Fastfetch,
    Powershell,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotObservation {
    schema: String,
    healthy: bool,
    available: bool,
    collected_at_utc: String,
    collector: SnapshotCollector,
    fastfetch_available: bool,
    #[serde(deserialize_with = "nullable")]
    fastfetch_version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    os_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    os_version: Option<String>,
    #[serde(deserialize_with = "nullable")]
    os_build: Option<String>,
    #[serde(deserialize_with = "nullable")]
    kernel_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    kernel_release: Option<String>,
    #[serde(deserialize_with = "nullable")]
    kernel_architecture: Option<String>,
    #[serde(deserialize_with = "nullable")]
    cpu_name: Option<String>,
    #[serde(deserialize_with = "nullable")]
    cpu_vendor: Option<String>,
    #[serde(deserialize_with = "nullable")]
    physical_cores: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    logical_processors: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    cpu_max_frequency_mhz: Option<i64>,
    gpus: Vec<SnapshotGpuObservation>,
    #[serde(deserialize_with = "nullable")]
    memory_total_mb: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    memory_used_mb: Option<i64>,
    disks: Vec<SnapshotDiskObservation>,
    #[serde(deserialize_with = "nullable")]
    packages_total: Option<i64>,
    #[serde(deserialize_with = "nullable")]
    warning: Option<String>,
    #[serde(deserialize_with = "nullable")]
    error: Option<String>,
}

fn parse_as<T>(text: &str, probe: ProbeId) -> Result<Value, String>
where
    T: for<'de> Deserialize<'de> + Serialize + HasSchema,
{
    let parsed: T = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let expected = probe.schema();
    if parsed.schema() != expected {
        return Err(format!("schema must be {expected}"));
    }
    serde_json::to_value(&parsed).map_err(|error| error.to_string())
}

trait HasSchema {
    fn schema(&self) -> &str;
}

macro_rules! has_schema {
    ($($kind:ty),* $(,)?) => {
        $(impl HasSchema for $kind {
            fn schema(&self) -> &str {
                &self.schema
            }
        })*
    };
}

has_schema!(
    TransportObservation,
    OverviewObservation,
    NetworkObservation,
    ComfyUiObservation,
    ListenerObservation,
    GpuObservation,
    SnapshotObservation,
);

/// Validate one probe's stdout against its strict contract and return the
/// normalized observation, or the reason it was rejected.
pub(crate) fn validate_observation(text: &str, probe: ProbeId) -> Result<Value, String> {
    match probe {
        ProbeId::Transport => parse_as::<TransportObservation>(text, probe),
        ProbeId::Overview => parse_as::<OverviewObservation>(text, probe),
        ProbeId::Network => parse_as::<NetworkObservation>(text, probe),
        ProbeId::Comfyui => parse_as::<ComfyUiObservation>(text, probe),
        ProbeId::Listener => parse_as::<ListenerObservation>(text, probe),
        ProbeId::Gpu => parse_as::<GpuObservation>(text, probe),
        ProbeId::Snapshot => parse_as::<SnapshotObservation>(text, probe),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn sample(probe: ProbeId) -> Value {
        match probe {
            ProbeId::Transport => json!({
                "schema": "rdbg.doctor.transport.v1",
                "healthy": true,
                "computer_name": "BOX-A",
                "powershell_version": "5.1",
                "powershell_edition": "Desktop",
                "remote_time_utc": "2026-01-01T00:00:00Z",
                "encoding_sentinel": "中文 / テスト / ✓",
                "apostrophe_sentinel": "O'Reilly",
                "dollar_sentinel": "$notExpanded",
                "json_literal_ok": true,
                "multiline_ok": true
            }),
            ProbeId::Overview => json!({
                "schema": "rdbg.doctor.overview.v1",
                "healthy": true,
                "computer_name": "BOX-A",
                "powershell_version": "5.1",
                "os_caption": "Windows",
                "os_version": "10.0",
                "os_build": "26100",
                "last_boot_utc": "2026-01-01T00:00:00Z",
                "uptime_seconds": 3600,
                "memory_total_mb": 32768,
                "memory_free_mb": 16384.5,
                "cpu_name": "CPU",
                "logical_processors": 16,
                "services": [
                    {"name": "sshd", "status": "Running", "present": true, "running": true}
                ]
            }),
            ProbeId::Network => json!({
                "schema": "rdbg.doctor.network.v1",
                "healthy": true,
                "computer_name": "BOX-A",
                "adapters": [{
                    "alias": "Ethernet",
                    "description": "Adapter",
                    "ipv4": ["192.0.2.10"],
                    "gateways": ["192.0.2.1"],
                    "dns": ["192.0.2.53"]
                }],
                "ssh_port_22": true,
                "comfyui_port": 8188,
                "comfyui_listening": true,
                "collection_error": null
            }),
            ProbeId::Comfyui => json!({
                "schema": "rdbg.doctor.comfyui.v1",
                "healthy": true,
                "reachable": true,
                "base_uri": "http://127.0.0.1:8188",
                "version": "1.0.0",
                "expected_version": "1.0.0",
                "version_matches": true,
                "queue_running": 0,
                "queue_pending": 0,
                "devices": [
                    {"name": "cuda:0 GPU", "type": "cuda", "vram_total_mb": 16000, "vram_free_mb": 12000}
                ],
                "error": null
            }),
            ProbeId::Listener => json!({
                "schema": "rdbg.doctor.listener.v1",
                "healthy": true,
                "port": 8188,
                "listening": true,
                "verdict": "canonical",
                "service_pid": 10,
                "all_owners_service_bound": true,
                "all_owners_canonical_python": true,
                "processes": [{
                    "pid": 100,
                    "name": "python.exe",
                    "executable": "C:\\canonical\\python.exe",
                    "parent_pid": 10,
                    "service_bound": true,
                    "canonical_python_in_lineage": true,
                    "lineage": [{
                        "depth": 0,
                        "pid": 100,
                        "name": "python.exe",
                        "executable": "C:\\canonical\\python.exe",
                        "parent_pid": 10,
                        "found": true,
                        "query_error": null
                    }]
                }],
                "expected_service": "Svc",
                "canonical_python": "C:\\canonical\\python.exe",
                "service": {"name": "Svc", "status": "Running", "present": true, "process_id": 10},
                "collection_error": null,
                "service_collection_error": null
            }),
            ProbeId::Gpu => json!({
                "schema": "rdbg.doctor.gpu.v1",
                "healthy": true,
                "available": true,
                "collected_at_utc": "2026-01-01T00:00:00Z",
                "devices": [{
                    "index": 0,
                    "name": "Test GPU",
                    "driver_version": "1.2",
                    "memory_total_mb": 16000,
                    "memory_used_mb": 1000,
                    "memory_free_mb": 15000,
                    "utilization_gpu_pct": 1,
                    "utilization_memory_pct": 2.5,
                    "temperature_c": 50.0,
                    "power_draw_w": 59.53,
                    "power_limit_w": 300.0,
                    "pstate": "P8"
                }],
                "compute_processes": [
                    {"pid": 101, "process_name": "python.exe", "used_memory_mb": 2048}
                ],
                "warning": null,
                "error": null
            }),
            ProbeId::Snapshot => json!({
                "schema": "rdbg.doctor.snapshot.v1",
                "healthy": true,
                "available": true,
                "collected_at_utc": "2026-01-01T00:00:00Z",
                "collector": "fastfetch",
                "fastfetch_available": true,
                "fastfetch_version": "fastfetch 2.0.0",
                "os_name": "Windows",
                "os_version": "10.0",
                "os_build": "26100",
                "kernel_name": "Windows NT",
                "kernel_release": "10.0",
                "kernel_architecture": "x86_64",
                "cpu_name": "CPU",
                "cpu_vendor": "Vendor",
                "physical_cores": 8,
                "logical_processors": 16,
                "cpu_max_frequency_mhz": 5000,
                "gpus": [{"name": "Test GPU", "vendor": "Vendor", "driver": "1.2", "type": "Discrete"}],
                "memory_total_mb": 32768,
                "memory_used_mb": 16384,
                "disks": [{"filesystem": "NTFS", "total_mb": 1000, "used_mb": 400, "available_mb": 600}],
                "packages_total": 42,
                "warning": null,
                "error": null
            }),
        }
    }

    fn check(value: &Value, probe: ProbeId) -> Result<Value, String> {
        validate_observation(&value.to_string(), probe)
    }

    /// Visit every object reachable from `value`, yielding a JSON pointer to it.
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
    fn every_probe_sample_passes_and_round_trips() {
        for probe in ProbeId::ALL {
            let value = sample(probe);
            let normalized = check(&value, probe).unwrap_or_else(|error| {
                panic!("{} sample rejected: {error}", probe.id());
            });
            assert_eq!(normalized["schema"], probe.schema());
        }
    }

    #[test]
    fn integer_is_accepted_where_a_float_is_expected() {
        let normalized = check(&sample(ProbeId::Gpu), ProbeId::Gpu).unwrap();
        assert_eq!(normalized["devices"][0]["utilization_gpu_pct"], json!(1.0));
    }

    #[test]
    fn extra_key_fails_at_every_object_level() {
        for probe in ProbeId::ALL {
            let value = sample(probe);
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
                    check(&mutated, probe).is_err(),
                    "{} accepted an extra key at '{pointer}'",
                    probe.id()
                );
            }
        }
    }

    #[test]
    fn deleting_any_required_key_fails() {
        for probe in ProbeId::ALL {
            let value = sample(probe);
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
                    // The only optional key in every contract.
                    if probe == ProbeId::Network && key == "description" {
                        continue;
                    }
                    let mut mutated = value.clone();
                    mutated
                        .pointer_mut(&pointer)
                        .unwrap()
                        .as_object_mut()
                        .unwrap()
                        .remove(&key);
                    assert!(
                        check(&mutated, probe).is_err(),
                        "{} accepted a missing '{pointer}/{key}'",
                        probe.id()
                    );
                    checked += 1;
                }
            }
            assert!(checked > 5, "{} checked only {checked} keys", probe.id());
        }
    }

    #[test]
    fn network_adapter_description_may_be_omitted() {
        let mut value = sample(ProbeId::Network);
        value["adapters"][0]
            .as_object_mut()
            .unwrap()
            .remove("description");
        let normalized = check(&value, ProbeId::Network).unwrap();
        assert_eq!(normalized["adapters"][0]["description"], Value::Null);
    }

    #[test]
    fn nullable_keys_accept_null() {
        let mut value = sample(ProbeId::Comfyui);
        for key in [
            "version",
            "expected_version",
            "queue_running",
            "queue_pending",
        ] {
            value[key] = Value::Null;
        }
        assert!(check(&value, ProbeId::Comfyui).is_ok());
    }

    #[test]
    fn strict_types_reject_coercions() {
        let cases: &[(ProbeId, &str, Value)] = &[
            (ProbeId::Transport, "healthy", json!("yes")),
            (ProbeId::Transport, "computer_name", json!(1)),
            (ProbeId::Overview, "logical_processors", json!(16.5)),
            (ProbeId::Overview, "uptime_seconds", json!("3600")),
            (ProbeId::Overview, "memory_total_mb", json!(true)),
            (ProbeId::Network, "comfyui_port", json!("8188")),
            (ProbeId::Listener, "verdict", json!("unknown")),
            (ProbeId::Snapshot, "collector", json!("other")),
            (ProbeId::Gpu, "healthy", json!(null)),
        ];
        for (probe, key, replacement) in cases {
            let mut value = sample(*probe);
            value[*key] = replacement.clone();
            assert!(
                check(&value, *probe).is_err(),
                "{} accepted {key} = {replacement}",
                probe.id()
            );
        }
    }

    #[test]
    fn wrong_or_foreign_schema_fails() {
        let mut value = sample(ProbeId::Transport);
        value["schema"] = json!("rdbg.doctor.transport.v2");
        assert!(check(&value, ProbeId::Transport).is_err());
        let overview = sample(ProbeId::Overview);
        assert!(check(&overview, ProbeId::Transport).is_err());
    }
}
