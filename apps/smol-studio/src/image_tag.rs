//! Reviewed local image aliases through the selected Docker context.
use std::{
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub source_id: String,
    pub reference: String,
    pub previous_id: Option<String>,
}

pub fn reference(input: &str) -> Result<String, String> {
    crate::storage::validate_reference(input)?;
    if input.contains('@') {
        return Err("Use a repository and tag, not a digest reference.".into());
    }
    let tail = input.rsplit('/').next().unwrap_or_default();
    if tail.is_empty() || tail.ends_with(':') {
        return Err("Enter a repository and a non-empty tag.".into());
    }
    Ok(if tail.contains(':') {
        input.into()
    } else {
        format!("{input}:latest")
    })
}

fn decode_inspect(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    code: Option<i32>,
) -> Result<Option<String>, String> {
    if !success {
        let error = String::from_utf8_lossy(stderr);
        // Only the engine's explicit missing-image response means an unused tag;
        // transport, permission and syntax errors must remain failures.
        if error.lines().any(|line| {
            line.starts_with("Error response from daemon: No such image:")
                || line.starts_with("Error: No such image:")
        }) {
            return Ok(None);
        }
        return Err(crate::runtime::runtime_error(stderr, code));
    }
    let id = String::from_utf8_lossy(stdout).trim().to_owned();
    crate::storage::validate_image_id(&id)?;
    Ok(Some(id))
}

fn inspect(
    reference: &str,
    deadline: Instant,
    shutdown: &AtomicBool,
) -> Result<Option<String>, String> {
    let mut command = crate::docker::docker_command();
    command.args([
        "--context",
        "smol",
        "image",
        "inspect",
        "--format",
        "{{.Id}}",
        reference,
    ]);
    let output = crate::runtime::capture_process(
        &mut command,
        deadline.saturating_duration_since(Instant::now()),
        64 * 1024,
        shutdown,
    )?;
    decode_inspect(output.success, &output.stdout, &output.stderr, output.code)
}

fn review_before(
    source_id: &str,
    target: &str,
    deadline: Instant,
    shutdown: &AtomicBool,
) -> Result<Plan, String> {
    crate::storage::validate_image_id(source_id)?;
    let reference = reference(target)?;
    if inspect(source_id, deadline, shutdown)?.as_deref() != Some(source_id) {
        return Err("The selected image is no longer available. Refresh the image list.".into());
    }
    let previous_id = inspect(&reference, deadline, shutdown)?;
    Ok(Plan {
        source_id: source_id.into(),
        reference,
        previous_id,
    })
}

pub fn review(source_id: &str, target: &str, shutdown: &AtomicBool) -> Result<Plan, String> {
    review_before(
        source_id,
        target,
        Instant::now() + Duration::from_secs(20),
        shutdown,
    )
}

pub fn apply(plan: &Plan, shutdown: &AtomicBool) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let current = review_before(&plan.source_id, &plan.reference, deadline, shutdown)?;
    if current.previous_id != plan.previous_id {
        return Err("This tag changed after review. Review it again before applying.".into());
    }
    if current.previous_id.as_deref() == Some(&current.source_id) {
        return Ok(());
    }
    let mut command = crate::docker::docker_command();
    command.args([
        "--context",
        "smol",
        "image",
        "tag",
        &current.source_id,
        &current.reference,
    ]);
    let output = crate::runtime::capture_process(
        &mut command,
        deadline.saturating_duration_since(Instant::now()),
        64 * 1024,
        shutdown,
    )?;
    if !output.success {
        return Err(crate::runtime::runtime_error(&output.stderr, output.code));
    }
    // Docker tagging has no compare-and-swap primitive. Recheck the result and
    // report concurrent edits; never undo another client's tag operation.
    if inspect(&current.reference, deadline, shutdown)?.as_deref() != Some(&current.source_id) {
        return Err("The tag does not point to this image after applying. Refresh and review its current destination.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_defaults_do_not_confuse_registry_ports_with_tags() {
        assert_eq!(reference("my-app").unwrap(), "my-app:latest");
        assert_eq!(
            reference("localhost:5000/team/app").unwrap(),
            "localhost:5000/team/app:latest"
        );
        assert_eq!(
            reference("registry.example:5000/team/app:Dev").unwrap(),
            "registry.example:5000/team/app:Dev"
        );
        for invalid in ["", "--help", "a b", "repo:", "repo/", "app@sha256:abc"] {
            assert!(reference(invalid).is_err(), "{invalid}");
        }
    }
    #[test]
    fn unavailable_engine_is_not_an_unused_destination() {
        let id = format!("sha256:{}", "a".repeat(64));
        assert_eq!(
            decode_inspect(true, id.as_bytes(), b"", Some(0)).unwrap(),
            Some(id)
        );
        assert_eq!(
            decode_inspect(
                false,
                b"",
                b"Error response from daemon: No such image: app:dev\n",
                Some(1)
            )
            .unwrap(),
            None
        );
        for error in [
            "Cannot connect to the Docker daemon",
            "permission denied",
            "invalid reference format",
        ] {
            assert!(decode_inspect(false, b"", error.as_bytes(), Some(1)).is_err());
        }
        assert!(decode_inspect(true, b"wrong-id", b"", Some(0)).is_err());
    }
    #[test]
    #[ignore = "requires two owned images in an isolated Smol Docker context"]
    fn live_image_tag_review_apply_and_stale_destination() {
        let a = std::env::var("SMOL_STUDIO_TEST_IMAGE_A").expect("owned source image");
        let b = std::env::var("SMOL_STUDIO_TEST_IMAGE_B").expect("owned second image");
        let target = std::env::var("SMOL_STUDIO_TEST_IMAGE_TAG").expect("owned destination tag");
        assert_ne!(a, b);
        let stop = AtomicBool::new(false);
        let initial = review(&a, &target, &stop).unwrap();
        assert!(initial.previous_id.is_none());
        let intervening = review(&b, &target, &stop).unwrap();
        apply(&intervening, &stop).unwrap();
        assert!(
            apply(&initial, &stop)
                .unwrap_err()
                .contains("changed after review")
        );
        let replacement = review(&a, &target, &stop).unwrap();
        assert_eq!(replacement.previous_id.as_deref(), Some(b.as_str()));
        apply(&replacement, &stop).unwrap();
        let same = review(&a, &target, &stop).unwrap();
        assert_eq!(same.previous_id.as_deref(), Some(a.as_str()));
        apply(&same, &stop).unwrap();
    }
}
