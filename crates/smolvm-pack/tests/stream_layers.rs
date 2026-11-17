//! The streaming layer path: a host that unpacks a pack's layers itself unpacks
//! each `layers/<digest>.tar` member as it streams past, so the tar is never
//! written and read back, and the tree still only appears under its own name
//! once the whole archive and its digest have matched.
//!
//! Every platform runs these. The trees land in the entry's own `layers/` on
//! Linux and Windows, and on macOS inside the entry's case-sensitive volume,
//! which is what the case-colliding check relies on.
//!
//! Its own test binary: `set_host_layers_probe` is process-wide, and the other
//! integration tests must keep the decision of the engine that runs them.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::extract::{
    force_detach_layers_volume, host_layer_store, is_extracted, PARTIAL_DIR_SUFFIX,
    STREAMED_LAYERS_FILE,
};
use smolvm_pack::format::PackManifest;
use smolvm_pack::{read_footer_from_sidecar, sidecar_path_for, Packer};

/// A host whose libkrun serves the override xattr (`krun_add_virtiofs4` is in
/// the bundled `libkrun.so`).
///
/// Only the probe is forced: streaming runs by default on Linux and macOS, so
/// the suite exercises that default rather than an opt-in. `stream_layers_off`
/// is the binary that pins the `SMOLVM_STREAM_LAYERS=off` escape hatch.
fn host_that_streams_layers() {
    smolvm_pack::extract::set_host_layers_probe(|| true);
}

/// A directory on a filesystem that stores user xattrs: the streaming path
/// needs them for the archived owners, and `TMPDIR` may be a tmpfs without
/// them. `CARGO_TARGET_TMPDIR` is inside the crate's target dir.
///
/// macOS mounts the case-sensitive volume *at* a directory inside this one, and
/// only allows a mount point on the boot volume — so a `CARGO_TARGET_DIR` on an
/// external volume makes every streaming test fail at `hdiutil attach`.
fn scratch() -> tempfile::TempDir {
    let root = if cfg!(target_os = "macos") {
        std::env::temp_dir()
    } else {
        Path::new(env!("CARGO_TARGET_TMPDIR")).to_path_buf()
    };
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix("stream-layers-")
        .tempdir_in(root)
        .unwrap()
}

/// Whether `dir` can hold `a` and `A` as two entries. NTFS and a default APFS
/// volume cannot, so an image whose paths differ only in case cannot survive
/// extraction there — a limitation of the host filesystem, not of streaming.
fn stores_case_distinct_names(dir: &Path) -> bool {
    let lower = dir.join("case-probe-a");
    let upper = dir.join("case-probe-A");
    let distinct = fs::write(&lower, b"lower").is_ok()
        && fs::write(&upper, b"upper").is_ok()
        && fs::read(&lower).is_ok_and(|bytes| bytes == b"lower");
    let _ = fs::remove_file(&lower);
    let _ = fs::remove_file(&upper);
    distinct
}

/// Release the case-sensitive volume a streaming macOS test left mounted, so
/// the scratch directory can be removed afterwards. A no-op elsewhere.
struct LayersVolume(PathBuf);

impl Drop for LayersVolume {
    fn drop(&mut self) {
        force_detach_layers_volume(&self.0);
    }
}

/// macOS streams into a mounted case-sensitive volume, which needs `hdiutil`.
/// Sandboxes and CI images without it skip rather than fail: the path under
/// test cannot run there at all.
fn skip_without_hdiutil() -> bool {
    #[cfg(target_os = "macos")]
    {
        if std::process::Command::new("hdiutil")
            .arg("-help")
            .output()
            .is_err()
        {
            eprintln!("SKIP: hdiutil is unavailable, macOS layers-stream tests need it");
            return true;
        }
    }
    false
}

/// Whether this host streams the pack's layers while extracting them — the
/// precondition for these tests, and the same decision the extractor makes.
/// Both host-unpack modes stream, including a root Linux host that restores
/// the archive's owners itself. An unprivileged Linux host without the
/// override-xattr probe, or a cache directory whose filesystem has no user
/// xattrs, answers no; skip rather than assert a path that cannot run.
fn host_streams_layers(sidecar: &Path, pack_dir: &Path) -> bool {
    let manifest = smolvm_pack::packer::read_manifest_from_sidecar(sidecar).unwrap();
    smolvm_pack::extract::host_streams_layers(Some(&manifest.smolvm_version), pack_dir)
}

fn layer_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (filename, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, filename, *content)
            .unwrap();
    }
    builder.into_inner().unwrap()
}

fn digest_of(layer: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(layer))
}

/// A pack carrying the given layers, bottom→top, each under the digest of its
/// own bytes.
fn build_sidecar(dir: &Path, layers: &[&[u8]]) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let stub = dir.join("stub");
    fs::write(&stub, b"#!/bin/sh\necho stub").unwrap();
    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    for layer in layers {
        collector.add_layer(&digest_of(layer), layer).unwrap();
    }
    let manifest = PackManifest::new(
        "test:latest".to_string(),
        digest_of(layers[0]),
        "linux/x86_64".to_string(),
        "linux/x86_64".to_string(),
    );
    let output = dir.join("packed");
    Packer::new(manifest)
        .with_stub(&stub)
        .with_assets(collector)
        .pack(&output)
        .unwrap();
    sidecar_path_for(&output)
}

/// The id a pack gave a layer: the digest hex, which is also its directory name.
fn layer_id(layer: &[u8]) -> String {
    digest_of(layer).trim_start_matches("sha256:").to_string()
}

/// Where readers of an entry find its layer trees: the entry's own `layers/` on
/// Linux and Windows, the case-sensitive volume on macOS.
fn entry_layers(pack_dir: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        host_layer_store(pack_dir, false).expect("the layer volume must resolve")
    } else {
        pack_dir.join("layers")
    }
}

/// Where streaming installs the trees: the entry's own volume (`layers/`, or the
/// case-sensitive volume on macOS). Readers see the same place: see
/// [`entry_layers`].
fn streamed_into(_shared_root: &Path, pack_dir: &Path) -> PathBuf {
    entry_layers(pack_dir)
}

/// A pack entry's directory for a shared extraction, and the store root.
fn entry_and_root(tmp: &Path, sidecar: &Path) -> (PathBuf, PathBuf, smolvm_pack::PackFooter) {
    let footer = read_footer_from_sidecar(sidecar).unwrap();
    let shared_root = tmp.join("_shared");
    let pack_dir = shared_root.join(format!("{:08x}", footer.checksum));
    fs::create_dir_all(&pack_dir).unwrap();
    (pack_dir, shared_root, footer)
}

#[test]
fn a_streamed_layer_lands_without_staging_its_tar() {
    host_that_streams_layers();
    if skip_without_hdiutil() {
        return;
    }
    let tmp = scratch();
    let layer = layer_tar(&[("etc/streamed.conf", b"streamed layer bytes")]);
    let id = layer_id(&layer);
    let sidecar = build_sidecar(&tmp.path().join("pack"), &[&layer]);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }
    let _volume = LayersVolume(pack_dir.clone());

    let shared =
        smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false)
            .unwrap();
    assert_eq!(shared, pack_dir);

    let streamed = streamed_into(&shared_root, &pack_dir).join(&id);
    assert!(
        streamed.is_dir(),
        "the layer must be installed at {}",
        streamed.display()
    );
    let staging = streamed.with_file_name(format!("{id}{PARTIAL_DIR_SUFFIX}"));
    assert!(!staging.exists(), "the staging directory must be renamed");

    let view = entry_layers(&pack_dir);
    assert!(
        !view.join(format!("{id}.tar")).exists()
            && !pack_dir.join("layers").join(format!("{id}.tar")).exists(),
        "streaming must not stage the layer tar"
    );
    assert_eq!(
        fs::read(view.join(&id).join("etc/streamed.conf")).unwrap(),
        b"streamed layer bytes",
        "the entry must present the layer under its own name"
    );

    // A warm hit reuses the entry and changes nothing.
    let again =
        smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false)
            .unwrap();
    assert_eq!(again, shared);
    assert!(view.join(&id).join("etc/streamed.conf").is_file());
}

/// A layer whose bytes do not hash to the name the pack gives it is not kept as
/// a streamed layer, and the pack still extracts: the whole extraction falls
/// back to the staged layout every smolvm before streaming produced, with a
/// warning. Single-layer exports re-create their tar, so their names are not
/// content addresses, and refusing them would break those packs.
#[test]
fn a_streamed_layer_whose_name_lies_falls_back_to_the_staged_layout() {
    host_that_streams_layers();
    if skip_without_hdiutil() {
        return;
    }
    let tmp = scratch();
    let layer = layer_tar(&[("etc/streamed.conf", b"streamed layer bytes")]);
    let claimed = format!("sha256:{}", "0".repeat(64));
    let dir = tmp.path().join("pack");
    fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub");
    fs::write(&stub, b"#!/bin/sh\necho stub").unwrap();
    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    collector.add_layer(&claimed, &layer).unwrap();
    let manifest = PackManifest::new(
        "test:latest".to_string(),
        claimed.clone(),
        "linux/x86_64".to_string(),
        "linux/x86_64".to_string(),
    );
    let output = dir.join("packed");
    Packer::new(manifest)
        .with_stub(&stub)
        .with_assets(collector)
        .pack(&output)
        .unwrap();
    let sidecar = sidecar_path_for(&output);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }
    let _volume = LayersVolume(pack_dir.clone());

    smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false)
        .expect("a pack whose names are not digests must still extract");
    assert!(
        !entry_layers(&pack_dir)
            .join(format!("{}{PARTIAL_DIR_SUFFIX}", "0".repeat(64)))
            .exists(),
        "the failed streamed attempt must leave no staging tree behind"
    );
    assert!(
        pack_dir
            .join("layers")
            .join("0".repeat(64) + ".tar")
            .is_file(),
        "the fallback stages the tar exactly as before streaming existed"
    );
    assert_eq!(
        fs::read(
            entry_layers(&pack_dir)
                .join("0".repeat(64))
                .join("etc/streamed.conf")
        )
        .unwrap(),
        b"streamed layer bytes",
        "the staged layer must still be unpacked for the host"
    );
    assert!(is_extracted(&pack_dir));
}

/// A streamed layer whose archive stops short is an error, not a layer: the
/// digest of the bytes is what the name says, so the verification passes and
/// the nested unpack is what fails. Nothing may be kept under the layer's name,
/// and the extraction must not read as complete.
#[test]
fn a_truncated_streamed_layer_is_refused_and_nothing_is_kept() {
    host_that_streams_layers();
    if skip_without_hdiutil() {
        return;
    }
    let tmp = scratch();
    let full = layer_tar(&[("etc/cut.conf", &[7u8; 64 * 1024])]);
    let cut = full[..full.len() / 2].to_vec();
    let id = layer_id(&cut);
    let sidecar = build_sidecar(&tmp.path().join("pack"), &[&cut]);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }
    let _volume = LayersVolume(pack_dir.clone());

    let error =
        smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false)
            .expect_err("a truncated layer archive must not extract");
    assert!(
        !error.to_string().contains("digest mismatch"),
        "the bytes match their name; the archive is what is wrong: {error}"
    );
    assert!(
        !entry_layers(&pack_dir).join(&id).exists()
            && !entry_layers(&pack_dir)
                .join(format!("{id}{PARTIAL_DIR_SUFFIX}"))
                .exists(),
        "no tree of the truncated layer may be kept, complete or partial"
    );
    assert!(!is_extracted(&pack_dir));
}

/// A crash mid-extraction leaves the finished layers exactly as they were and
/// only the interrupted one is done again: the rerun drains and verifies the
/// member whose tree is already installed instead of rebuilding it.
#[test]
fn a_resumed_extraction_leaves_the_layers_that_finished_alone() {
    host_that_streams_layers();
    if skip_without_hdiutil() {
        return;
    }
    let tmp = scratch();
    let first = layer_tar(&[("etc/first.conf", b"first layer")]);
    let second = layer_tar(&[("etc/second.conf", b"second layer")]);
    let (first_id, second_id) = (layer_id(&first), layer_id(&second));
    let sidecar = build_sidecar(&tmp.path().join("pack"), &[&first, &second]);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }
    let _volume = LayersVolume(pack_dir.clone());

    smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();
    assert!(is_extracted(&pack_dir));

    let streamed = streamed_into(&shared_root, &pack_dir);
    let finished = streamed.join(&first_id);
    let before = fs::metadata(finished.join("etc/first.conf")).unwrap();
    let before_dir = fs::metadata(&finished).unwrap();

    // The state a kill during the second layer leaves behind: the interrupted
    // layer still under its `.partial` name, no tree of its own, and no
    // completion marker for the extraction as a whole.
    let interrupted = streamed.join(&second_id);
    fs::remove_dir_all(&interrupted).unwrap();
    let _ = fs::remove_dir_all(entry_layers(&pack_dir).join(&second_id));
    let staging = streamed.join(format!("{second_id}{PARTIAL_DIR_SUFFIX}"));
    fs::create_dir_all(staging.join("etc")).unwrap();
    fs::write(staging.join("etc/second.conf"), b"half written").unwrap();
    fs::remove_file(pack_dir.join(".smolvm-extracted")).unwrap();
    assert!(!is_extracted(&pack_dir));

    smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();

    let after = fs::metadata(finished.join("etc/first.conf")).unwrap();
    let after_dir = fs::metadata(&finished).unwrap();
    assert_eq!(
        before.modified().unwrap(),
        after.modified().unwrap(),
        "the finished layer's file must not be rewritten"
    );
    assert_eq!(
        before_dir.modified().unwrap(),
        after_dir.modified().unwrap(),
        "the finished layer's directory must not be touched"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            before.ino(),
            after.ino(),
            "the finished layer's inode must be kept"
        );
    }
    assert_eq!(
        fs::read(interrupted.join("etc/second.conf")).unwrap(),
        b"second layer",
        "the interrupted layer must be redone from the pack"
    );
    assert!(
        !staging.exists(),
        "the leftover staging directory must be discarded"
    );
    assert!(is_extracted(&pack_dir));
    assert_eq!(
        fs::read(
            entry_layers(&pack_dir)
                .join(&second_id)
                .join("etc/second.conf")
        )
        .unwrap(),
        b"second layer",
        "the entry must present the redone layer"
    );
}

/// Streaming leaves no tar behind, which is what the healing check
/// (`cached_layers_usable`) reads for a staged extraction: the extraction
/// records what it installed instead, so an entry that lost its layers is
/// still seen and re-extracted rather than trusted.
#[test]
fn a_streamed_extraction_records_what_it_installed() {
    host_that_streams_layers();
    if skip_without_hdiutil() {
        return;
    }
    let tmp = scratch();
    let layer = layer_tar(&[("etc/recorded.conf", b"recorded")]);
    let id = layer_id(&layer);
    let sidecar = build_sidecar(&tmp.path().join("pack"), &[&layer]);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }
    let _volume = LayersVolume(pack_dir.clone());

    smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();

    let record = pack_dir.join("layers").join(STREAMED_LAYERS_FILE);
    assert!(
        record.is_file(),
        "a streamed extraction must record its layers at {}",
        record.display()
    );
    assert_eq!(fs::read_to_string(&record).unwrap().trim(), id);
    assert!(
        smolvm_pack::extract::cached_layers_usable(&pack_dir),
        "a streamed entry with its layers in place must read as usable"
    );

    // Deleting the layer has to be visible to the healing check. On macOS the
    // trees are inside the case-sensitive volume, whose own file is the
    // evidence that survives an unmount; the Linux tree is the evidence itself.
    #[cfg(not(target_os = "macos"))]
    {
        fs::remove_dir_all(entry_layers(&pack_dir).join(&id)).unwrap();
        assert!(
            !smolvm_pack::extract::cached_layers_usable(&pack_dir),
            "an entry whose streamed layers were deleted must not read as usable"
        );
    }
}

/// A streaming extraction writes no tar, so the size the *staged* path
/// preflights from is gone: the manifest's layer sizes have to stand in, or an
/// extraction that cannot fit discovers it part-way through the first 53 GB
/// layer instead of before it starts.
///
/// The manifest is what is trusted here, so the test lies in it: the pack
/// carries one tiny layer whose entry claims several terabytes.
#[cfg(not(target_os = "macos"))]
#[test]
fn a_streamed_extraction_refuses_a_pack_it_cannot_fit() {
    host_that_streams_layers();
    let tmp = scratch();
    let layer = layer_tar(&[("etc/tiny.conf", b"tiny")]);
    let id = layer_id(&layer);
    let dir = tmp.path().join("pack");
    fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub");
    fs::write(&stub, b"#!/bin/sh\necho stub").unwrap();
    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    collector.add_layer(&digest_of(&layer), &layer).unwrap();
    let mut packer = Packer::new(PackManifest::new(
        "test:latest".to_string(),
        digest_of(&layer),
        "linux/x86_64".to_string(),
        "linux/x86_64".to_string(),
    ))
    .with_stub(&stub)
    .with_assets(collector);
    // The collector stages the real member; the manifest is the inventory the
    // extractor reads, and it is the one that lies.
    packer.manifest_mut().assets.layers[0].size = 4 * 1024 * 1024 * 1024 * 1024;
    let output = dir.join("packed");
    packer.pack(&output).unwrap();
    let sidecar = sidecar_path_for(&output);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }

    let error =
        smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false)
            .expect_err("a pack whose layers cannot fit must be refused before the unpack");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::StorageFull,
        "got: {error}"
    );
    assert!(
        error.to_string().contains("the packed image layers"),
        "got: {error}"
    );
    assert!(
        !streamed_into(&shared_root, &pack_dir).join(&id).exists(),
        "nothing may be installed when the preflight refuses the pack"
    );
}

/// Linux image layers really do carry paths that differ only in case
/// (`/usr/bin/gdebi` next to `/usr/lib/GDebi/`), and a host that extracts them
/// onto a case-insensitive filesystem silently drops one variant — the guest
/// then boots a corrupt image. Streaming must land the trees on the
/// case-sensitive volume on macOS, not on the volume the cache directory sits
/// on, so both paths survive.
#[test]
fn a_case_colliding_layer_survives_streaming() {
    host_that_streams_layers();
    if skip_without_hdiutil() {
        return;
    }
    let tmp = scratch();
    if !stores_case_distinct_names(tmp.path()) {
        eprintln!("SKIP: this filesystem is case-insensitive; the paths cannot coexist");
        return;
    }
    let layer = layer_tar(&[
        ("usr/lib/GDebi/data.txt", b"upper"),
        ("usr/lib/gdebi/data.txt", b"lower"),
    ]);
    let id = layer_id(&layer);
    let sidecar = build_sidecar(&tmp.path().join("pack"), &[&layer]);
    let (pack_dir, shared_root, footer) = entry_and_root(tmp.path(), &sidecar);
    if !host_streams_layers(&sidecar, &pack_dir) {
        eprintln!("SKIP: this host does not unpack pack layers itself");
        return;
    }
    let _volume = LayersVolume(pack_dir.clone());

    smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();

    let lib = entry_layers(&pack_dir).join(&id).join("usr/lib");
    let mut names: Vec<String> = fs::read_dir(&lib)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec!["GDebi".to_string(), "gdebi".to_string()],
        "paths differing only in case must both survive streaming"
    );
    assert_eq!(fs::read(lib.join("GDebi/data.txt")).unwrap(), b"upper");
    assert_eq!(fs::read(lib.join("gdebi/data.txt")).unwrap(), b"lower");
}
