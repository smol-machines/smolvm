//! Network metadata for the desktop; driver options and labels are not retained.
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct Subnet {
    pub subnet: String,
    pub gateway: String,
    pub range: String,
}
#[derive(Clone, Debug)]
pub struct Endpoint {
    pub id: String,
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
}
#[derive(Clone, Debug)]
pub struct Details {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub scope: String,
    pub internal: Option<bool>,
    pub ipv6: Option<bool>,
    pub subnets: Vec<Subnet>,
    pub endpoints: Vec<Endpoint>,
}
pub fn validate_id(id: &str) -> Result<(), String> {
    if id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("Choose a network with a full ID.".into())
    }
}
impl Details {
    pub fn parse(id: &str, bytes: &[u8]) -> Result<Self, String> {
        validate_id(id)?;
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|_| "Docker returned invalid network details.")?;
        if v["Id"].as_str() != Some(id) {
            return Err("Docker returned a different network.".into());
        }
        let get = |v: &Value, key: &str| v[key].as_str().unwrap_or_default().to_owned();
        let subnets = v["IPAM"]["Config"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| Subnet {
                subnet: get(v, "Subnet"),
                gateway: get(v, "Gateway"),
                range: get(v, "IPRange"),
            })
            .collect();
        let mut endpoints: Vec<_> = v["Containers"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(id, v)| Endpoint {
                id: id.clone(),
                name: get(v, "Name"),
                ipv4: get(v, "IPv4Address"),
                ipv6: get(v, "IPv6Address"),
            })
            .collect();
        endpoints.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(Self {
            id: id.into(),
            name: get(&v, "Name"),
            driver: get(&v, "Driver"),
            scope: get(&v, "Scope"),
            internal: v["Internal"].as_bool(),
            ipv6: v["EnableIPv6"].as_bool(),
            subnets,
            endpoints,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_dual_stack_endpoints_and_missing_capabilities() {
        let id = "a".repeat(64);
        let v = serde_json::json!({"Id":id,"Name":"app","Driver":"bridge","Internal":false,
            "IPAM":{"Config":[{"Subnet":"10.1.0.0/24","Gateway":"10.1.0.1"},{"Subnet":"fd00::/64","Gateway":"fd00::1"}]},
            "Containers":{"abcd":{"Name":"web","IPv4Address":"10.1.0.2/24","IPv6Address":"fd00::2/64"}},
            "Options":{"password":"secret"},"Labels":{"secret":"secret"}});
        let details = Details::parse(&id, &serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(details.subnets.len(), 2);
        assert_eq!(details.endpoints[0].ipv6, "fd00::2/64");
        assert_eq!(details.internal, Some(false));
        assert_eq!(details.ipv6, None);
        assert!(!format!("{details:?}").contains("secret"));
        assert!(Details::parse(&"b".repeat(64), &serde_json::to_vec(&v).unwrap()).is_err());
        for id in ["--verbose", "abcd", "", "name"] {
            assert!(validate_id(id).is_err());
        }
    }
}
