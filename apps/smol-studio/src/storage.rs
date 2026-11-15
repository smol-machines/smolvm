//! Display only storage metadata; image environments and volume driver options
//! can contain secrets and are not retained.
use crate::docker::Kind;
use serde_json::Value;

#[derive(Clone, Debug)]
pub struct User {
    pub id: String,
    pub name: String,
    pub state: String,
}
#[derive(Clone, Debug)]
pub struct Details {
    pub kind: Kind,
    pub id: String,
    pub created: String,
    pub fields: Vec<(String, String)>,
    pub users: Vec<User>,
}
pub fn validate_image_id(id: &str) -> Result<(), String> {
    match id.strip_prefix("sha256:") {
        Some(hash) if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()) => Ok(()),
        _ => Err("Choose an image with a full SHA-256 ID.".into()),
    }
}
pub fn validate_volume(name: &str) -> Result<(), String> {
    if name.len() <= 255
        && name
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        Ok(())
    } else {
        Err("Use a volume name starting with a letter or number, containing only letters, numbers, dots, underscores, or hyphens.".into())
    }
}
pub fn validate_reference(reference: &str) -> Result<(), String> {
    if reference.is_empty()
        || reference.len() > 512
        || reference.starts_with('-')
        || reference
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        Err(
            "Enter an image reference, such as alpine:3.22 or registry.example/team/image:tag."
                .into(),
        )
    } else {
        Ok(())
    }
}
impl Details {
    pub fn parse(kind: Kind, id: &str, bytes: &[u8]) -> Result<Self, String> {
        let v: Value = serde_json::from_slice(bytes)
            .map_err(|_| "Docker returned invalid storage details.")?;
        let get = |key: &str| v[key].as_str().unwrap_or_default().to_owned();
        let created;
        let fields = match kind {
            Kind::Images => {
                validate_image_id(id)?;
                if get("Id") != id {
                    return Err("Docker returned a different image.".into());
                }
                created = get("Created");
                let tags = v["RepoTags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n");
                vec![
                    (
                        "Tags".into(),
                        if tags.is_empty() {
                            "Untagged".into()
                        } else {
                            tags
                        },
                    ),
                    (
                        "Platform".into(),
                        format!("{}/{}", get("Os"), get("Architecture")),
                    ),
                    (
                        "Image size".into(),
                        v["Size"]
                            .as_u64()
                            .map(bytes_label)
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    ("Created".into(), display_time(&created)),
                    ("Image ID".into(), id.into()),
                ]
            }
            Kind::Volumes => {
                validate_volume(id)?;
                if get("Name") != id {
                    return Err("Docker returned a different volume.".into());
                }
                created = get("CreatedAt");
                vec![
                    ("Driver".into(), get("Driver")),
                    ("Scope".into(), get("Scope")),
                    ("Created".into(), display_time(&created)),
                    ("Storage path".into(), get("Mountpoint")),
                ]
            }
            _ => return Err("Choose an image or volume.".into()),
        };
        Ok(Self {
            kind,
            id: id.into(),
            created,
            fields,
            users: vec![],
        })
    }
}
fn display_time(value: &str) -> String {
    if let Some((date, time)) = value.strip_suffix('Z').and_then(|v| v.split_once('T')) {
        format!("{date} {} UTC", time.split('.').next().unwrap_or(time))
    } else {
        value.to_owned()
    }
}
pub fn bytes_label(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.1} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{bytes} bytes")
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn projects_metadata_without_environment_or_driver_secrets() {
        let id = format!("sha256:{}", "a".repeat(64));
        let v = serde_json::json!({"Id":id,"RepoTags":["app:one","app:two"],"Os":"linux","Architecture":"arm64","Size":1024,"Config":{"Env":["TOKEN=secret"]}});
        let d = Details::parse(Kind::Images, &id, &serde_json::to_vec(&v).unwrap()).unwrap();
        assert!(d.fields[0].1.contains("app:two"));
        assert!(!format!("{d:?}").contains("secret"));
        let v = br#"{"Name":"app-data","Driver":"local","Mountpoint":"/data","CreatedAt":"now","Options":{"password":"secret"}}"#;
        let d = Details::parse(Kind::Volumes, "app-data", v).unwrap();
        assert!(!format!("{d:?}").contains("secret"));
        assert!(Details::parse(Kind::Volumes, "other", v).is_err());
        for name in ["", "--force", "../data", "/data", "a b"] {
            assert!(validate_volume(name).is_err());
        }
        assert!(validate_volume("app-data_2.0").is_ok());
        assert!(validate_image_id("abc123").is_err());
        assert!(validate_reference("--all-tags").is_err());
        assert!(validate_reference("registry.example:5000/app:tag").is_ok());
    }
}
