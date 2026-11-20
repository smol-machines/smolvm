//! The cache belongs to the guest, including while a host request is cancelled.
use parking_lot::Mutex;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Weak},
};

type Preparation = Arc<Mutex<()>>;
type Preparations = Mutex<HashMap<PathBuf, Weak<Mutex<()>>>>;
static PREPARATIONS: LazyLock<Preparations> = LazyLock::new(Default::default);

pub(super) fn for_image(path: &Path) -> Preparation {
    let mut preparations = PREPARATIONS.lock();
    preparations.retain(|_, lock| lock.strong_count() > 0);
    if let Some(lock) = preparations.get(path).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(Mutex::new(()));
    preparations.insert(path.to_owned(), Arc::downgrade(&lock));
    lock
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Barrier,
        },
        time::Duration,
    };

    #[test]
    fn concurrent_requests_flatten_one_complete_archive_once() {
        let directory = tempfile::tempdir().unwrap();
        let packed = directory.path().join("packed");
        std::fs::create_dir(&packed).unwrap();
        let archive = packed.join(super::super::ARCHIVE_FILE_NAME);
        let mut builder = tar::Builder::new(std::fs::File::create(&archive).unwrap());
        let mut header = tar::Header::new_gnu();
        header.set_size(65536);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "payload", vec![42; 65536].as_slice())
            .unwrap();
        builder.finish().unwrap();
        drop(builder);
        let output = directory.path().join("flattened");
        let starts = AtomicUsize::new(0);
        let barrier = Barrier::new(4);
        std::thread::scope(|scope| {
            for _ in 0..4 {
                scope.spawn(|| {
                    barrier.wait();
                    let resolved = super::super::ensure_archive_flattened_at(
                        &packed,
                        output.clone(),
                        |stage, _| {
                            if stage == "flattening local image archive" {
                                starts.fetch_add(1, Ordering::SeqCst);
                                // Widen the destructive rebuild window so a racing
                                // request would remove the first request's rootfs.
                                std::thread::sleep(Duration::from_millis(50));
                            }
                        },
                        |archive, rootfs, _| {
                            tar::Archive::new(std::fs::File::open(archive)?).unpack(rootfs)?;
                            Ok(Some(b"{}".to_vec()))
                        },
                    )
                    .unwrap()
                    .unwrap();
                    assert_eq!(
                        std::fs::read(
                            resolved
                                .join(super::super::ARCHIVE_ROOTFS_DIR)
                                .join("payload")
                        )
                        .unwrap(),
                        vec![42; 65536]
                    );
                });
            }
        });
        assert_eq!(starts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failed_materialization_is_rebuilt_before_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let packed = directory.path().join("packed");
        std::fs::create_dir(&packed).unwrap();
        std::fs::write(
            packed.join(super::super::ARCHIVE_FILE_NAME),
            b"archive fixture",
        )
        .unwrap();
        let output = directory.path().join("flattened");
        let failed = super::super::ensure_archive_flattened_at(
            &packed,
            output.clone(),
            |_, _| {},
            |_, rootfs, _| {
                std::fs::write(rootfs.join("partial"), b"unfinished")?;
                Err(std::io::Error::other("interrupted extraction").into())
            },
        );
        assert!(failed.is_err());
        assert!(!output.join(super::super::ARCHIVE_EXTRACTED_MARKER).exists());
        super::super::ensure_archive_flattened_at(
            &packed,
            output.clone(),
            |_, _| {},
            |_, rootfs, _| {
                assert!(!rootfs.join("partial").exists());
                std::fs::write(rootfs.join("complete"), b"finished")?;
                Ok(Some(b"{}".to_vec()))
            },
        )
        .unwrap();
        assert!(output
            .join(super::super::ARCHIVE_EXTRACTED_MARKER)
            .is_file());
    }

    #[test]
    fn different_images_do_not_share_a_preparation_lock() {
        let directory = tempfile::tempdir().unwrap();
        let first = for_image(&directory.path().join("one"));
        let second = for_image(&directory.path().join("two"));
        let _held = first.lock();
        assert!(second.try_lock().is_some());
    }
}
