use super::*;
use std::io::{self, BufWriter};

impl AgentClient {
    /// Stream a folder into exactly `destination`, preserving links and merging
    /// existing directories. No host-side archive or whole-file buffer is used.
    /// A failed upload closes this connection to discard the guest's staging.
    pub fn upload_directory<F: FnMut(u64)>(
        &mut self,
        source: &Path,
        destination: &str,
        mut progress: F,
    ) -> Result<u64> {
        let metadata = source
            .symlink_metadata()
            .map_err(|e| Error::agent("read source folder", e.to_string()))?;
        if !metadata.is_dir() {
            return Err(Error::config(
                "files",
                "Choose a folder, not a file or symbolic link.",
            ));
        }
        let result = (|| {
            let response = self.request(&AgentRequest::DirectoryWriteBegin {
                path: destination.into(),
                target: self.file_target.clone(),
            })?;
            expect_ok(response, "begin folder upload")?;
            let sink = DirectoryWriter {
                client: self,
                progress: &mut progress,
                sent: 0,
                failed: false,
                finished: false,
            };
            let mut archive =
                tar::Builder::new(BufWriter::with_capacity(FILE_WRITE_CHUNK_SIZE, sink));
            archive.follow_symlinks(false);
            if let Err(error) = archive.append_dir_all(".", source) {
                archive.get_mut().get_mut().abort();
                return Err(Error::agent("archive source folder", error.to_string()));
            }
            let mut output = archive
                .into_inner()
                .map_err(|e| Error::agent("finish folder archive", e.to_string()))?;
            output
                .flush()
                .map_err(|e| Error::agent("upload folder", e.to_string()))?;
            let writer = output.get_mut();
            writer.chunk(&[], true)?;
            Ok(writer.sent)
        })();
        if result.is_err() {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
        result
    }
}

struct DirectoryWriter<'a, F> {
    client: &'a mut AgentClient,
    progress: &'a mut F,
    sent: u64,
    failed: bool,
    finished: bool,
}
impl<F: FnMut(u64)> DirectoryWriter<'_, F> {
    fn abort(&mut self) {
        self.failed = true;
        let _ = self.client.stream.shutdown(std::net::Shutdown::Both);
    }
    fn chunk(&mut self, data: &[u8], done: bool) -> Result<()> {
        if self.failed {
            return Err(Error::agent("upload folder", "Folder upload has stopped."));
        }
        let result = self.send_chunk(data, done);
        if result.is_err() {
            // BufWriter retries buffered output during Drop. Stop the transport
            // before unwinding so rejected archive bytes cannot be sent again.
            self.abort();
        }
        result
    }
    fn send_chunk(&mut self, data: &[u8], done: bool) -> Result<()> {
        let total = self
            .sent
            .checked_add(data.len() as u64)
            .filter(|size| *size <= FILE_TRANSFER_MAX_TOTAL)
            .ok_or_else(|| Error::agent("upload folder", "Folder archives support up to 4 GiB."))?;
        let mut response = self.client.request_with_write_idle_timeout(
            &AgentRequest::FileWriteChunk {
                data: data.to_vec(),
                done,
            },
            Duration::from_secs(FILE_WRITE_IDLE_TIMEOUT_SECS),
        )?;
        while done && matches!(response, AgentResponse::Progress { .. }) {
            response = self.client.receive()?;
        }
        expect_ok(response, "upload folder")?;
        self.sent = total;
        self.finished = done;
        (self.progress)(total);
        Ok(())
    }
}
impl<F: FnMut(u64)> Write for DirectoryWriter<'_, F> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let length = data.len().min(FILE_WRITE_CHUNK_SIZE);
        self.chunk(&data[..length], false)
            .map_err(|e| io::Error::other(e.to_string()))?;
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<F> Drop for DirectoryWriter<'_, F> {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.client.stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn request(peer: &mut UdsStream) -> AgentRequest {
        let mut size = [0; 4];
        peer.read_exact(&mut size).unwrap();
        let size = u32::from_be_bytes(size);
        assert!(size <= MAX_FRAME_SIZE);
        let mut body = vec![0; size as usize];
        peer.read_exact(&mut body).unwrap();
        smolvm_protocol::binary_stream::decode_request(&body)
            .unwrap()
            .body
    }
    fn reply(peer: &mut UdsStream, response: AgentResponse) {
        peer.write_all(&encode_message(&response).unwrap()).unwrap();
    }

    #[test]
    fn folder_upload_streams_bounded_frames_and_preserves_names_links_and_modes() {
        for binary in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            std::fs::create_dir_all(source.join("empty")).unwrap();
            let name = "café 雪\nfile";
            let payload = vec![42; FILE_WRITE_CHUNK_SIZE * 2 + 7];
            std::fs::write(source.join(name), &payload).unwrap();
            std::fs::set_permissions(source.join(name), std::fs::Permissions::from_mode(0o751))
                .unwrap();
            symlink(name, source.join("link")).unwrap();
            let (stream, mut peer) = UdsStream::pair().unwrap();
            let server = std::thread::spawn(move || {
                assert!(
                    matches!(request(&mut peer), AgentRequest::DirectoryWriteBegin { path, target: Some(WorkloadTarget::Vm) } if path == "/workspace/chosen")
                );
                reply(&mut peer, AgentResponse::Ok { data: None });
                let mut archive = Vec::new();
                loop {
                    let AgentRequest::FileWriteChunk { data, done } = request(&mut peer) else {
                        panic!("upload chunk");
                    };
                    assert!(data.len() <= FILE_WRITE_CHUNK_SIZE);
                    archive.extend(data);
                    if done {
                        reply(
                            &mut peer,
                            AgentResponse::Progress {
                                message: "extracting".into(),
                                percent: None,
                                layer: None,
                            },
                        );
                    }
                    reply(&mut peer, AgentResponse::Ok { data: None });
                    if done {
                        break;
                    }
                }
                archive
            });
            let mut client = AgentClient::from_stream(stream);
            client.file_target = Some(WorkloadTarget::Vm);
            client.binary_stream.store(binary, Ordering::Release);
            let mut progress = Vec::new();
            let sent = client
                .upload_directory(&source, "/workspace/chosen", |bytes| progress.push(bytes))
                .unwrap();
            let archive = server.join().unwrap();
            assert_eq!(sent, archive.len() as u64);
            assert_eq!(progress.last(), Some(&sent));
            assert!(progress.windows(2).all(|pair| pair[0] <= pair[1]));
            let destination = root.path().join("saved");
            tar::Archive::new(&archive[..])
                .unpack(&destination)
                .unwrap();
            assert_eq!(std::fs::read(destination.join(name)).unwrap(), payload);
            assert_eq!(
                std::fs::read_link(destination.join("link")).unwrap(),
                Path::new(name)
            );
            assert_eq!(
                destination
                    .join(name)
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o751
            );
            assert!(destination.join("empty").is_dir());
            assert!(!destination.join("source").exists());
        }
    }

    #[test]
    fn failed_folder_upload_closes_the_stream_before_returning() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("file"), b"contents").unwrap();
        let (stream, mut peer) = UdsStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server = std::thread::spawn(move || {
            assert!(matches!(
                request(&mut peer),
                AgentRequest::DirectoryWriteBegin { .. }
            ));
            reply(&mut peer, AgentResponse::Ok { data: None });
            assert!(matches!(
                request(&mut peer),
                AgentRequest::FileWriteChunk { .. }
            ));
            reply(
                &mut peer,
                AgentResponse::error("disk full", "FILE_IO_FAILED"),
            );
            assert_eq!(
                peer.read(&mut [0; 1]).unwrap(),
                0,
                "failed upload retained its staging connection"
            );
        });
        let mut client = AgentClient::from_stream(stream);
        assert!(client
            .upload_directory(root.path(), "/workspace/chosen", |_| {})
            .is_err());
        server.join().unwrap();
    }

    #[test]
    #[ignore = "requires an owned running SMOLVM_DIRECTORY_UPLOAD_MACHINE with matching guest"]
    fn live_streaming_cancel_discards_staging_and_retry_succeeds() {
        let name = std::env::var("SMOLVM_DIRECTORY_UPLOAD_MACHINE").unwrap();
        assert!(name.starts_with("studio-folder-upload-"));
        let record = crate::db::SmolvmDb::open()
            .unwrap()
            .get_vm(&name)
            .unwrap()
            .unwrap();
        let manager = crate::agent::AgentManager::for_vm(&name).unwrap();
        manager.detach();
        assert!(
            manager.try_connect_existing().is_some(),
            "owned fixture is not running"
        );
        let target = crate::workload::machine_target(&record);
        let mut client = manager.connect().unwrap();
        client.use_target(target.clone()).unwrap();
        let destination = "/workspace/studio-upload-stream";
        assert!(!client
            .list_directory("/workspace")
            .unwrap()
            .iter()
            .any(|entry| entry.name == "studio-upload-stream"));
        let source = tempfile::tempdir().unwrap();
        let bytes = vec![42; 8 * FILE_WRITE_CHUNK_SIZE];
        std::fs::write(source.path().join("file"), &bytes).unwrap();
        let interrupt = client.stream.try_clone().unwrap();
        let mut cancelled = false;
        let result = client.upload_directory(source.path(), destination, |sent| {
            if sent >= FILE_WRITE_CHUNK_SIZE as u64 && !cancelled {
                cancelled = true;
                interrupt.shutdown(std::net::Shutdown::Both).unwrap();
            }
        });
        assert!(cancelled && result.is_err());
        drop(client);
        let mut client = manager.connect().unwrap();
        client.use_target(target.clone()).unwrap();
        assert!(!client
            .list_directory("/workspace")
            .unwrap()
            .iter()
            .any(|entry| entry.name == "studio-upload-stream"));
        client.use_target(WorkloadTarget::Vm).unwrap();
        assert!(
            !client
                .list_directory("/storage/tmp")
                .unwrap()
                .iter()
                .any(|entry| entry.name.starts_with(".smol-directory-upload-")),
            "cancelled upload leaked staging"
        );
        client.use_target(target).unwrap();
        client
            .upload_directory(source.path(), destination, |_| {})
            .unwrap();
        assert_eq!(
            client
                .read_file("/workspace/studio-upload-stream/file")
                .unwrap(),
            bytes
        );
        // Folder downloads must resolve through the same workload mounts as
        // uploads and single-file reads, including an image's /workspace bind.
        let archive = source.path().join("saved.tar");
        client
            .archive_directory_to_path(destination, &archive, |_| {})
            .unwrap();
        let saved = source.path().join("saved");
        tar::Archive::new(std::fs::File::open(archive).unwrap())
            .unpack(&saved)
            .unwrap();
        assert_eq!(std::fs::read(saved.join("file")).unwrap(), bytes);
    }
}
