//! End-to-end test of the shared, content-addressed pack extraction
//! (`extract_sidecar_shared`) against a *real* `.smolmachine` sidecar — real
//! zstd stream, real tar, real footer/checksum — on a real filesystem.
//!
//! Linux-only: the shared store backs the Linux fleet's per-VM idmapped bind
//! mount (kernel ≥5.12); macOS uses a per-machine case-sensitive sparse image,
//! so the whole module compiles to nothing elsewhere. This validates the
//! *extraction half* (extract-once, content-addressed, locked down); the mount
//! half is validated by the root crate's `tests/idmap_mount.rs`.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use smolvm_pack::assets::AssetCollector;
use smolvm_pack::extract::{extract_sidecar, extract_sidecar_shared, shared_extract_enabled};
use smolvm_pack::format::PackManifest;
use smolvm_pack::{read_footer_from_sidecar, sidecar_path_for, Packer};

/// Build a tiny but *valid* OCI-style layer: a raw tar archive carrying one
/// file. `post_process_extraction` untars every `layers/*.tar`, so the payload
/// must be a real tar (a raw byte blob would fail with "failed to read entire
/// block" — exactly what a real OCI layer never does).
fn layer_tar(filename: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, filename, content).unwrap();
    builder.into_inner().unwrap()
}

/// Build a real sidecar `.smolmachine` carrying two OCI layers, returning the
/// sidecar path (under `dir`).
fn build_real_sidecar(dir: &Path) -> std::path::PathBuf {
    let stub_path = dir.join("stub");
    fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    collector
        .add_layer(
            "sha256:aaa111aaa111bbb222",
            &layer_tar("etc/base.conf", b"base layer file"),
        )
        .unwrap();
    collector
        .add_layer(
            "sha256:ccc333ccc333ddd444",
            &layer_tar("etc/top.conf", b"top layer file"),
        )
        .unwrap();

    let manifest = PackManifest::new(
        "test:latest".to_string(),
        "sha256:test".to_string(),
        "linux/x86_64".to_string(),
        "linux/x86_64".to_string(),
    );

    let output = dir.join("packed");
    Packer::new(manifest)
        .with_stub(&stub_path)
        .with_assets(collector)
        .pack(&output)
        .unwrap();

    sidecar_path_for(&output)
}

/// Recursively collect (relative-path -> file bytes) for every regular file in a
/// tree, so the shared extraction can be compared byte-for-byte to a plain one.
fn file_map(root: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    let mut out = std::collections::BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d).unwrap() {
            let entry = entry.unwrap();
            let ft = entry.file_type().unwrap();
            let p = entry.path();
            if ft.is_dir() {
                stack.push(p);
            } else if ft.is_file() {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().to_string();
                out.insert(rel, fs::read(&p).unwrap());
            }
        }
    }
    out
}

#[test]
fn shared_extraction_is_content_addressed_idempotent_and_locked_down() {
    let tmp = tempfile::tempdir().unwrap();
    let sidecar = build_real_sidecar(tmp.path());
    let footer = read_footer_from_sidecar(&sidecar).unwrap();

    let shared_root = tmp.path().join("_shared");
    let pack_plain = tmp.path().join("vm-plain/pack");

    // First machine extracts into the shared store; a plain per-machine
    // extraction is the byte-for-byte reference.
    let shared_dir = extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();
    extract_sidecar(&sidecar, &pack_plain, &footer, false, false).unwrap();

    // 1) Content-addressed: the shared copy lives at `_shared/<checksum>`.
    assert_eq!(
        shared_dir,
        shared_root.join(format!("{:08x}", footer.checksum)),
        "shared dir must be keyed by the footer checksum"
    );
    assert!(shared_dir.is_dir(), "shared extraction dir must exist");

    // 2) The shared view is byte-identical to a plain per-machine extraction —
    //    the idmapped mount only remaps ownership, never content.
    let reference = file_map(&pack_plain);
    assert!(!reference.is_empty(), "extraction produced no files");
    assert_eq!(
        file_map(&shared_dir),
        reference,
        "shared content must match a plain extraction byte-for-byte"
    );

    // 3) Idempotent reuse: a second machine with the same checksum reuses the one
    //    extracted tree — no second decode, no second store dir. This is the
    //    cold-start tax the shared store removes.
    let shared_dir2 = extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();
    assert_eq!(
        shared_dir2, shared_dir,
        "second machine must reuse the copy"
    );
    let store_dirs: Vec<_> = fs::read_dir(&shared_root)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    assert_eq!(
        store_dirs.len(),
        1,
        "only one content-addressed extraction may exist for one checksum"
    );

    // 4) Locked down to 0700: the store root and the checksum dir are owner-only,
    //    so a sibling VM dropped to a *different* uid cannot read the shared copy
    //    directly — it must go through its own idmapped mount (#456 isolation).
    for dir in [&shared_root, &shared_dir] {
        let mode = fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o700,
            "{} must be 0700, got {:o}",
            dir.display(),
            mode
        );
    }
}

#[test]
fn kill_switch_disables_the_shared_store() {
    // The handler consults `shared_extract_enabled()` to choose the shared vs
    // per-machine path; `SMOLVM_DISABLE_SHARED_EXTRACT` forces the fallback
    // without a redeploy. (Run as its own test fn so the env mutation cannot race
    // the content test on cargo's parallel test threads.)
    assert!(
        shared_extract_enabled(),
        "shared store should be enabled by default on Linux"
    );
    std::env::set_var("SMOLVM_DISABLE_SHARED_EXTRACT", "1");
    assert!(
        !shared_extract_enabled(),
        "kill-switch must disable the shared store"
    );
    std::env::remove_var("SMOLVM_DISABLE_SHARED_EXTRACT");
}

/// Like [`build_real_sidecar`] but mixes `marker` into the layer so the pack's
/// content checksum differs — lets us create two distinct shared entries.
fn build_real_sidecar_marked(dir: &Path, marker: &[u8]) -> std::path::PathBuf {
    fs::create_dir_all(dir).unwrap();
    let stub_path = dir.join("stub");
    fs::write(&stub_path, b"#!/bin/sh\necho stub").unwrap();

    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    collector
        .add_layer(
            "sha256:aaa111aaa111bbb222",
            &layer_tar("etc/base.conf", marker),
        )
        .unwrap();

    let manifest = PackManifest::new(
        "test:latest".to_string(),
        "sha256:test".to_string(),
        "linux/x86_64".to_string(),
        "linux/x86_64".to_string(),
    );
    let output = dir.join("packed");
    Packer::new(manifest)
        .with_stub(&stub_path)
        .with_assets(collector)
        .pack(&output)
        .unwrap();
    sidecar_path_for(&output)
}

#[test]
fn shared_store_is_not_lru_evicted_by_a_later_pack() {
    // Regression for the packed-layers store eviction: creating a second,
    // different-checksum pack must NOT LRU-evict the first shared entry. A pool VM
    // references a shared entry only through its `.pack-shared` pointer and holds
    // NO lease, so evicting it empties that VM's `/packed_layers` and every
    // connect/exec into it dies "no layer directories found" (exit 255).
    let tmp = tempfile::tempdir().unwrap();
    let shared_root = tmp.path().join("_shared");

    // Cap of 1 byte: were the shared store size-capped (the bug), writing the
    // second entry would evict the first. The fix routes shared extraction with
    // cap_cache=false, so the cap never applies to `_shared`. (Own test fn so the
    // env mutation cannot race the other tests on cargo's parallel threads.)
    std::env::set_var("SMOLVM_PACK_CACHE_MAX_BYTES", "1");

    let sa = build_real_sidecar_marked(&tmp.path().join("a"), b"alpha-layer");
    let fa = read_footer_from_sidecar(&sa).unwrap();
    let da = extract_sidecar_shared(&sa, &shared_root, &fa, false).unwrap();

    let sb = build_real_sidecar_marked(&tmp.path().join("b"), b"beta-layer-longer-bytes");
    let fb = read_footer_from_sidecar(&sb).unwrap();
    let db = extract_sidecar_shared(&sb, &shared_root, &fb, false).unwrap();

    std::env::remove_var("SMOLVM_PACK_CACHE_MAX_BYTES");

    assert_ne!(
        fa.checksum, fb.checksum,
        "test needs two distinct-checksum packs"
    );
    assert!(
        da.is_dir(),
        "first shared entry must SURVIVE a later extraction (not be LRU-evicted)"
    );
    assert!(db.is_dir(), "second shared entry must exist");
    // Both entries keep their extracted layer dirs (not just an empty shell).
    for d in [&da, &db] {
        let n = fs::read_dir(d.join("layers"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .count();
        assert!(n > 0, "{} must keep its layer dirs", d.display());
    }
}
