//! Remote volumes: mount S3-compatible object storage into a machine with the
//! same `-v SOURCE:GUEST[:ro]` flag as directory mounts.
//!
//! `s3://bucket[/prefix]` mounts a bucket. Credentials come from the machine's
//! `--env` (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, optional
//! `AWS_ENDPOINT_URL` for R2/MinIO and `AWS_REGION`); without them the bucket is
//! read anonymously, which covers public datasets. Anything else stays a host
//! directory mount handled by `HostMount`.
//!
//! The mount is performed by the agent itself, natively: it enters the workload
//! container's mount namespace and speaks FUSE and the S3 API directly. Nothing
//! is required of the image — no rclone, no fuse3, no `fusermount3` — so a
//! bucket can be mounted into a distroless or scratch image that could not
//! install a helper at all. Mounting happens between container create and start,
//! so the workload's first instruction already sees its data and its command is
//! never rewritten.
use serde::{Deserialize, Serialize};

/// One remote volume attached to a machine, stored on its record verbatim so
/// `status` can echo what the user wrote and the mount command can evolve
/// without migrating persisted state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteVolume {
    /// The user-supplied source (`s3://bucket[/prefix]`).
    pub source: String,
    /// Absolute guest mount point.
    pub target: String,
    /// Mount read-only.
    pub read_only: bool,
}

/// Split raw `-v` specs into host-directory specs (returned untouched for
/// `HostMount::parse`, preserving its validation and error messages) and
/// parsed remote volumes.
pub fn split_specs(specs: &[String]) -> crate::Result<(Vec<String>, Vec<RemoteVolume>)> {
    let mut host = Vec::new();
    let mut remote = Vec::new();
    for spec in specs {
        match parse_spec(spec)? {
            Some(volume) => remote.push(volume),
            None => host.push(spec.clone()),
        }
    }
    // Remote targets must not collide with each other; the caller checks
    // them against host mount targets once those are parsed.
    let mut seen = std::collections::HashSet::new();
    for volume in &remote {
        if !seen.insert(&volume.target) {
            return Err(crate::Error::config(
                "parse remote volume",
                format!(
                    "duplicate mount target: {} is specified more than once",
                    volume.target
                ),
            ));
        }
    }
    Ok((host, remote))
}

/// Parse one `-v` spec; `Ok(None)` means "not a remote source" and the spec
/// belongs to the host-directory path. Mirrors `HostMount`'s right-anchored
/// parse so sources may contain colons (an S3 URL's scheme does).
fn parse_spec(spec: &str) -> crate::Result<Option<RemoteVolume>> {
    let (rest, read_only) = match spec.rsplit_once(':') {
        Some((head, "ro")) => (head, true),
        Some((head, "rw")) => (head, false),
        _ => (spec, false),
    };
    let Some((source, target)) = rest.rsplit_once(':') else {
        return Ok(None);
    };
    let is_remote = source.starts_with("s3://") || source.starts_with(':');
    if !is_remote {
        return Ok(None);
    }
    if !target.starts_with('/') {
        return Err(crate::Error::config(
            "parse remote volume",
            format!("remote volume guest path must be absolute: '{spec}'"),
        ));
    }
    if target.contains(' ') {
        return Err(crate::Error::config(
            "parse remote volume",
            format!("remote volume guest path must not contain spaces: '{spec}'"),
        ));
    }
    // Both values end up inside a single-quoted shell word.
    if source.contains('\'') || target.contains('\'') {
        return Err(crate::Error::config(
            "parse remote volume",
            format!("remote volume spec must not contain single quotes: '{spec}'"),
        ));
    }
    let Some(bucket) = source.strip_prefix("s3://") else {
        // A leading colon is rclone's connection-string syntax. Mounting is now
        // native S3, so such a spec cannot be honoured — and silently treating
        // it as a bucket name would sign requests against a nonsense bucket.
        // Reject it here, where the spec is still visible to name in the error.
        return Err(crate::Error::config(
            "parse remote volume",
            format!(
                "'{spec}' is an rclone remote, which is no longer supported; \
                 use an S3 URL instead, e.g. 's3://bucket/prefix:/guest/path'"
            ),
        ));
    };
    if bucket.trim_matches('/').is_empty() {
        return Err(crate::Error::config(
            "parse remote volume",
            format!("s3 volume needs a bucket name: '{spec}'"),
        ));
    }
    Ok(Some(RemoteVolume {
        source: source.to_string(),
        target: target.to_string(),
        read_only,
    }))
}

/// Whether a structured mount source (the API's `MountSpec.source`) denotes a
/// remote volume rather than a host directory.
pub fn is_remote_source(source: &str) -> bool {
    source.starts_with("s3://") || source.starts_with(':')
}

/// Build a remote volume from already-split parts (the API's structured mount
/// spec), reusing the colon-spec parser so both entry points validate
/// identically.
pub fn from_parts(source: &str, target: &str, read_only: bool) -> crate::Result<RemoteVolume> {
    // The parser is right-anchored, so a colon in the target would mis-split
    // the reassembled spec; targets never legitimately contain one.
    if target.contains(':') {
        return Err(crate::Error::config(
            "parse remote volume",
            format!("remote volume guest path must not contain ':': '{target}'"),
        ));
    }
    let spec = format!("{source}:{target}{}", if read_only { ":ro" } else { "" });
    parse_spec(&spec)?.ok_or_else(|| {
        crate::Error::config(
            "parse remote volume",
            format!("not a remote volume source: '{source}'"),
        )
    })
}

impl RemoteVolume {
    /// Bucket name and key prefix parsed out of the `s3://bucket/prefix` source.
    fn bucket_and_prefix(&self) -> (String, String) {
        let rest = self.source.strip_prefix("s3://").unwrap_or(&self.source);
        match rest.trim_matches('/').split_once('/') {
            Some((bucket, prefix)) => (bucket.to_string(), prefix.trim_matches('/').to_string()),
            None => (rest.trim_matches('/').to_string(), String::new()),
        }
    }

    /// Build the structured mount request the agent performs natively.
    ///
    /// Credentials and endpoint are read from the machine's env, matching what
    /// every AWS SDK does, so an existing workload's configuration carries over
    /// unchanged. A bucket with no credentials is mounted anonymously rather
    /// than failing — that is exactly how public datasets are consumed.
    pub fn to_s3_volume(&self, env: &[(String, String)]) -> smolvm_protocol::S3Volume {
        let get = |key: &str| {
            env.iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_empty())
        };
        let (bucket, prefix) = self.bucket_and_prefix();
        let region = get("AWS_REGION")
            .or_else(|| get("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|| "us-east-1".to_string());
        let endpoint = get("AWS_ENDPOINT_URL")
            .or_else(|| get("AWS_ENDPOINT"))
            .unwrap_or_else(|| format!("https://s3.{region}.amazonaws.com"));
        smolvm_protocol::S3Volume {
            endpoint,
            region,
            bucket,
            prefix,
            mountpoint: self.target.clone(),
            read_only: self.read_only,
            access_key_id: get("AWS_ACCESS_KEY_ID"),
            secret_access_key: get("AWS_SECRET_ACCESS_KEY"),
            session_token: get("AWS_SESSION_TOKEN"),
        }
    }
}

/// Build the mount requests for every remote volume on a machine.
pub fn to_s3_volumes(
    volumes: &[RemoteVolume],
    env: &[(String, String)],
) -> Vec<smolvm_protocol::S3Volume> {
    volumes.iter().map(|v| v.to_s3_volume(env)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(specs: &[&str]) -> (Vec<String>, Vec<RemoteVolume>) {
        let specs: Vec<String> = specs.iter().map(|s| s.to_string()).collect();
        split_specs(&specs).unwrap()
    }

    #[test]
    fn s3_sugar_parses_with_mode() {
        let (host, remote) = split(&["s3://my-bucket/prefix:/mnt/data:ro"]);
        assert!(host.is_empty());
        assert_eq!(
            remote,
            vec![RemoteVolume {
                source: "s3://my-bucket/prefix".into(),
                target: "/mnt/data".into(),
                read_only: true,
            }]
        );
    }

    #[test]
    fn rejects_relative_guest_path_and_quotes_and_empty_bucket() {
        assert!(split_specs(&["s3://b:data".to_string()]).is_err());
        assert!(split_specs(&["s3://b:/it's:ro".to_string()]).is_err());
        assert!(split_specs(&["s3://:/d".to_string()]).is_err());
        assert!(split_specs(&["s3://b:/d".to_string(), "s3://c:/d".to_string()]).is_err());
    }

    // Mounting is native S3 now, so an rclone connection string cannot be
    // honoured. It must be named as unsupported rather than parsed as a bucket,
    // which would sign every request against a nonsense name.
    #[test]
    fn an_rclone_remote_is_rejected_by_name() {
        let err = split_specs(&[":s3,provider=Minio,endpoint=\"http://h\":b:/mnt/d".to_string()])
            .expect_err("an rclone remote must not parse as a bucket");
        let msg = err.to_string();
        assert!(msg.contains("rclone"), "{msg}");
        assert!(msg.contains("s3://"), "{msg}");
        // A remote with an empty path is still an rclone remote, not a host dir.
        assert!(split_specs(&[":http,url=\"https://h\"::/mnt/d".to_string()]).is_err());
        // Host directory mounts are untouched by the rejection.
        let (host, remote) = split_specs(&["/data:/mnt/d".to_string()]).unwrap();
        assert_eq!(host, vec!["/data:/mnt/d".to_string()]);
        assert!(remote.is_empty());
    }

    #[test]
    fn from_parts_matches_colon_parser() {
        let structured = from_parts("s3://bucket/pfx", "/mnt/d", true).unwrap();
        let parsed = &split(&["s3://bucket/pfx:/mnt/d:ro"]).1[0];
        assert_eq!(&structured, parsed);
        // Same validation as the colon parser: relative target, non-S3
        // source, empty bucket.
        assert!(from_parts("s3://b", "relative", false).is_err());
        assert!(from_parts(":http,url=\"https://h\"", "/mnt/x", false).is_err());
        assert!(from_parts("s3://", "/mnt/x", false).is_err());
        // Colon in a structured target would mis-split the reassembled spec.
        assert!(from_parts("s3://b", "/mnt/a:ro", false).is_err());
        assert!(!is_remote_source("/host/dir"));
        assert!(is_remote_source("s3://b"));
        assert!(is_remote_source(":http,url=\"https://h\":"));
    }
}

#[cfg(test)]
mod s3_spec_tests {
    use super::*;

    fn vol(source: &str) -> RemoteVolume {
        RemoteVolume {
            source: source.to_string(),
            target: "/mnt/data".to_string(),
            read_only: false,
        }
    }

    #[test]
    fn a_bucket_without_a_prefix_mounts_the_whole_bucket() {
        let v = vol("s3://my-bucket").to_s3_volume(&[]);
        assert_eq!(v.bucket, "my-bucket");
        assert_eq!(v.prefix, "");
        assert_eq!(v.mountpoint, "/mnt/data");
    }

    #[test]
    fn a_prefix_selects_a_sub_tree_of_the_bucket() {
        let v = vol("s3://my-bucket/nested/prefix").to_s3_volume(&[]);
        assert_eq!(v.bucket, "my-bucket");
        assert_eq!(v.prefix, "nested/prefix");
    }

    // A public dataset has no credentials; mounting anonymously is correct
    // rather than an error.
    #[test]
    fn no_credentials_means_anonymous_access() {
        let v = vol("s3://noaa-goes16").to_s3_volume(&[]);
        assert!(v.access_key_id.is_none());
        assert!(v.secret_access_key.is_none());
        assert_eq!(v.endpoint, "https://s3.us-east-1.amazonaws.com");
    }

    // The env names match what every AWS SDK reads, so an existing workload's
    // configuration carries over untouched.
    #[test]
    fn credentials_and_endpoint_come_from_the_machine_env() {
        let env = vec![
            ("AWS_ACCESS_KEY_ID".to_string(), "AKIA".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "secret".to_string()),
            (
                "AWS_ENDPOINT_URL".to_string(),
                "http://minio:9000".to_string(),
            ),
            ("AWS_REGION".to_string(), "eu-west-1".to_string()),
        ];
        let v = vol("s3://b").to_s3_volume(&env);
        assert_eq!(v.access_key_id.as_deref(), Some("AKIA"));
        assert_eq!(v.secret_access_key.as_deref(), Some("secret"));
        assert_eq!(v.endpoint, "http://minio:9000");
        assert_eq!(v.region, "eu-west-1");
    }

    #[test]
    fn the_region_shapes_the_default_aws_endpoint() {
        let env = vec![("AWS_DEFAULT_REGION".to_string(), "ap-south-1".to_string())];
        let v = vol("s3://b").to_s3_volume(&env);
        assert_eq!(v.endpoint, "https://s3.ap-south-1.amazonaws.com");
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        let env = vec![("AWS_ACCESS_KEY_ID".to_string(), String::new())];
        let v = vol("s3://b").to_s3_volume(&env);
        assert!(
            v.access_key_id.is_none(),
            "an empty key must not sign requests"
        );
    }

    #[test]
    fn read_only_carries_through_to_the_mount() {
        let mut r = vol("s3://b");
        r.read_only = true;
        assert!(r.to_s3_volume(&[]).read_only);
    }
}
