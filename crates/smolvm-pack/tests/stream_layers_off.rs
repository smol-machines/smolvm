//! What an extraction leaves behind with both new paths switched off.
//!
//! `SMOLVM_STREAM_LAYERS=off` has to reproduce the staged-tar layout a pack has always been extracted into: the
//! tar next to the layer's name, the tree the host unpacks beside it, and no
//! streamed-layers record. That layout is what every other reader (`pack export
//! --from-vm`, the in-guest unpack, `cached_layers_usable`) resolves against.
//!
//! Its own test binary: the env var and the host-layers probe are process-wide,
//! and the streaming tests in `stream_layers.rs` set them the other way.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::extract::{force_detach_layers_volume, host_layer_store, STREAMED_LAYERS_FILE};
use smolvm_pack::format::PackManifest;
use smolvm_pack::{read_footer_from_sidecar, sidecar_path_for, Packer};

fn scratch() -> tempfile::TempDir {
    // macOS mounts the case-sensitive volume at a directory inside this one,
    // and only allows a mount point on the boot volume; a target dir on an
    // external volume would fail at `hdiutil attach`.
    let root = if cfg!(target_os = "macos") {
        std::env::temp_dir()
    } else {
        Path::new(env!("CARGO_TARGET_TMPDIR")).to_path_buf()
    };
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix("stream-layers-off-")
        .tempdir_in(root)
        .unwrap()
}

struct LayersVolume(PathBuf);

impl Drop for LayersVolume {
    fn drop(&mut self) {
        force_detach_layers_volume(&self.0);
    }
}

#[test]
fn an_extraction_with_streaming_off_keeps_the_staged_tar_layout() {
    std::env::set_var("SMOLVM_STREAM_LAYERS", "off");
    smolvm_pack::extract::set_host_layers_probe(|| true);

    let tmp = scratch();
    let mut layer = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(b"staged layer bytes".len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    layer
        .append_data(&mut header, "etc/staged.conf", &b"staged layer bytes"[..])
        .unwrap();
    let layer = layer.into_inner().unwrap();
    let id = format!("{:x}", Sha256::digest(&layer));

    let dir = tmp.path().join("pack");
    fs::create_dir_all(&dir).unwrap();
    let stub = dir.join("stub");
    fs::write(&stub, b"#!/bin/sh\necho stub").unwrap();
    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    collector
        .add_layer(&format!("sha256:{id}"), &layer)
        .unwrap();
    let manifest = PackManifest::new(
        "test:latest".to_string(),
        format!("sha256:{id}"),
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
    let footer = read_footer_from_sidecar(&sidecar).unwrap();

    let shared_root = tmp.path().join("_shared");
    let pack_dir = shared_root.join(format!("{:08x}", footer.checksum));
    fs::create_dir_all(&pack_dir).unwrap();
    let _volume = LayersVolume(pack_dir.clone());

    smolvm_pack::extract::extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();

    assert!(
        pack_dir.join("layers").join(format!("{id}.tar")).is_file(),
        "with both paths off the layer tar must be staged exactly as before"
    );
    assert!(
        !pack_dir.join("layers").join(STREAMED_LAYERS_FILE).exists(),
        "a staged extraction must not record streamed layers"
    );
    assert!(
        smolvm_pack::extract::cached_layers_usable(&pack_dir),
        "the staged tar must resolve the healing check"
    );
    // This host unpacks the layers itself, so the tree is materialized from the
    // staged tar during post-processing — the stock behavior, unchanged.
    let tree = host_layer_store(&pack_dir, false).unwrap().join(&id);
    assert!(
        tree.join("etc/staged.conf").is_file(),
        "the staged tar must still be unpacked into {}",
        tree.display()
    );
}
