use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PortOwner {
    pub id: String,
    pub name: String,
    pub image: String,
}

pub fn published_owners(records: &JsonValue, port: u16) -> Result<Vec<PortOwner>, String> {
    let records = records
        .as_array()
        .ok_or("invalid container list for port preflight")?;
    Ok(records
        .iter()
        .filter(|record| {
            let state = record
                .get("State")
                .or_else(|| record.get("status"))
                .and_then(JsonValue::as_str);
            state == Some("running")
                && record
                    .get("Ports")
                    .or_else(|| record.get("ports"))
                    .and_then(JsonValue::as_array)
                    .is_some_and(|ports| {
                        ports.iter().any(|mapping| {
                            let tcp = mapping.get("Type").or_else(|| mapping.get("protocol")).and_then(JsonValue::as_str).unwrap_or("tcp") == "tcp";
                            tcp && mapping
                                .get("PublicPort")
                                .or_else(|| mapping.get("host_port"))
                                .and_then(JsonValue::as_u64)
                                == Some(u64::from(port))
                        })
                    })
        })
        .map(|record| PortOwner {
            id: record
                .get("Id")
                .or_else(|| record.get("id"))
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
            name: record
                .get("Names")
                .and_then(JsonValue::as_array)
                .and_then(|names| names.first())
                .or_else(|| record.get("name"))
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .trim_start_matches('/')
                .to_string(),
            image: record
                .get("Image")
                .or_else(|| record.get("image"))
                .and_then(JsonValue::as_str)
                .unwrap_or_default()
                .to_string(),
        })
        .collect())
}

pub fn verify_replacement(
    expected: &PortOwner,
    actual: Option<&PortOwner>,
    confirmation: &str,
) -> Result<(), String> {
    if expected.id.is_empty()
        || expected.name.is_empty()
        || confirmation != expected.name
        || actual != Some(expected)
    {
        return Err(
            "Port owner changed or confirmation does not match. Review the conflict again.".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_requires_exact_identity_and_explicit_name_confirmation() {
        let expected = PortOwner {
            id: "full-id".into(),
            name: "database".into(),
            image: "postgres:17".into(),
        };
        let changed = PortOwner {
            id: "different-id".into(),
            ..expected.clone()
        };
        assert!(verify_replacement(&expected, Some(&changed), "database").is_err());
        assert!(verify_replacement(&expected, Some(&expected), "").is_err());
        assert!(verify_replacement(&expected, None, "database").is_err());
        assert!(verify_replacement(&expected, Some(&expected), "database").is_ok());
    }
    #[test]
    fn udp_mappings_cannot_be_selected_as_tcp_replacement_owners() {
        let records = serde_json::json!([
            {"Id":"udp-service", "Names":["/dns"], "Image":"dns", "State":"running", "Ports":[{"PublicPort":5353, "Type":"udp"}]}
        ]);
        assert!(published_owners(&records, 5353).unwrap().is_empty());
    }
    #[test]
    fn stopped_containers_do_not_claim_ports_and_exact_ids_are_preserved() {
        let records = serde_json::json!([
            {"Id":"exact-id", "Names":["/database"], "Image":"postgres", "State":"running", "Ports":[{"PublicPort":5432}]},
            {"Id":"old-id", "Names":["/old"], "Image":"postgres", "State":"exited", "Ports":[{"PublicPort":5432}]}
        ]);
        let owners = published_owners(&records, 5432).unwrap();
        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].id, "exact-id");
        assert_eq!(owners[0].name, "database");
    }
}
