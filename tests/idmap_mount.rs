//! Validates the shared-pack idmapped-bind-mount mechanism on a real Linux
//! kernel (>= 5.12). This is the novel piece of the shared content-addressed
//! pack store: one root-owned copy of the build-constant pack is extracted per
//! node, then presented at each VM's `pack` mountpoint via an idmapped bind
//! mount that maps the on-disk uid/gid 0 down to the VM's dropped uid (#456).
//!
//! Root-only (needs CAP_SYS_ADMIN for unshare/open_tree/mount_setattr/move_mount)
//! and Linux-only, so it is `#[ignore]`d by default. Run on the test box with:
//!   sudo -E cargo test --release --test idmap_mount -- --ignored --test-threads=1
#![cfg(target_os = "linux")]

use std::os::unix::fs::MetadataExt;

/// A distinctive uid/gid well outside any real account, matching the
/// 2_000_000+ range #456 drops VMM processes into.
const TEST_UID: u32 = 2_000_123;
const TEST_GID: u32 = 2_000_123;

#[test]
#[ignore = "requires root (CAP_SYS_ADMIN) and Linux >= 5.12"]
fn idmap_mount_presents_root_owned_pack_as_vm_uid() {
    // SAFETY of the in-process mount-ns mutation: setup_pack_idmap_mount does
    // unshare(CLONE_NEWNS), so the bind mount is visible only to this thread's
    // private mount namespace and vanishes when the test process exits. Run with
    // --test-threads=1 so no sibling test races on the namespace.
    let root = std::env::temp_dir().join(format!("smolvm-idmap-test-{}", std::process::id()));
    let shared = root.join("shared");
    let target = root.join("target");
    std::fs::create_dir_all(&shared).expect("mkdir shared");
    std::fs::create_dir_all(&target).expect("mkdir target");

    // A root-owned (extraction-as-root => uid 0) file + nested dir, mirroring the
    // agent-rootfs tree the real pack contains.
    let file = shared.join("hello");
    std::fs::write(&file, b"pack contents").expect("write shared file");
    let nested_dir = shared.join("sub");
    std::fs::create_dir_all(&nested_dir).expect("mkdir nested");
    let nested_file = nested_dir.join("deep");
    std::fs::write(&nested_file, b"deep contents").expect("write nested file");

    // Precondition: on disk the files are owned by uid/gid 0.
    let pre = std::fs::metadata(&file).expect("stat pre");
    assert_eq!(pre.uid(), 0, "shared file must start root-owned");
    assert_eq!(pre.gid(), 0, "shared file must start root-group");

    // Exercise the mechanism under test.
    smolvm::process::setup_pack_idmap_mount(&shared, &target, TEST_UID, TEST_GID)
        .expect("setup_pack_idmap_mount failed");

    // Through the idmapped mount, on-disk uid 0 must surface as the VM uid — this
    // is what lets the soon-to-drop VMM read every pack file as its owner.
    let mapped = std::fs::metadata(target.join("hello")).expect("stat mapped file");
    assert_eq!(
        mapped.uid(),
        TEST_UID,
        "idmapped mount must surface on-disk uid 0 as the VM uid"
    );
    assert_eq!(
        mapped.gid(),
        TEST_GID,
        "idmapped mount must surface on-disk gid 0 as the VM gid"
    );
    // Contents must read through unchanged (it is the same inode, just remapped).
    let body = std::fs::read(target.join("hello")).expect("read mapped file");
    assert_eq!(body, b"pack contents", "mapped file contents must match");

    // AT_RECURSIVE must remap nested entries too, not just the top level.
    let mapped_deep =
        std::fs::metadata(target.join("sub").join("deep")).expect("stat mapped nested");
    assert_eq!(
        mapped_deep.uid(),
        TEST_UID,
        "nested entries must be remapped (AT_RECURSIVE)"
    );

    // Isolation invariant: the underlying shared copy is untouched on disk — a
    // sibling VM dropped to a *different* uid still sees it as root-only and so
    // cannot read it directly (only its own idmapped view maps it).
    let post = std::fs::metadata(&file).expect("stat post");
    assert_eq!(post.uid(), 0, "on-disk shared copy must stay root-owned");

    // Best-effort cleanup; the private mount ns tears down on process exit anyway.
    let _ = std::fs::remove_dir_all(&root);
}
