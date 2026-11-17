//! Bounded, aligned bulk writes; integrity covers logical bytes, not padding.
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

#[cfg(target_os = "linux")]
const ALIGN: usize = 4096;
/// Bytes per direct write. Large writes reach more of a device's queue.
#[cfg(any(target_os = "linux", test))]
const CAPACITY: usize = 8 * 1024 * 1024;
/// Full buffers written concurrently behind the packer. A direct write blocks
/// for the device's latency, so one at a time caps a network disk at a few
/// tens of MB/s however fast compression is.
#[cfg(target_os = "linux")]
const IN_FLIGHT: usize = 4;

pub(crate) enum ArtifactWriter {
    Buffered(File),
    #[cfg(target_os = "linux")]
    Aligned(AlignedWriter),
}

/// An aligned allocation of [`CAPACITY`] bytes.
#[cfg(target_os = "linux")]
struct AlignedBuffer {
    bytes: Vec<u8>,
    start: usize,
}

#[cfg(target_os = "linux")]
impl AlignedBuffer {
    fn new() -> Self {
        let bytes = vec![0_u8; CAPACITY + ALIGN];
        let start = bytes.as_ptr().align_offset(ALIGN);
        Self { bytes, start }
    }

    fn get(&self) -> &[u8] {
        &self.bytes[self.start..self.start + CAPACITY]
    }

    fn get_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[self.start..self.start + CAPACITY]
    }
}

/// Threads writing full buffers at their offsets, returning each buffer
/// (or the write's error) when done.
#[cfg(target_os = "linux")]
struct WritePool {
    jobs: Option<std::sync::mpsc::SyncSender<(AlignedBuffer, u64)>>,
    done: std::sync::mpsc::Receiver<io::Result<AlignedBuffer>>,
    threads: Vec<std::thread::JoinHandle<()>>,
    in_flight: usize,
    allocated: usize,
    free: Vec<AlignedBuffer>,
}

#[cfg(target_os = "linux")]
impl WritePool {
    fn spawn(file: &std::sync::Arc<File>) -> io::Result<Self> {
        let (jobs, queue) = std::sync::mpsc::sync_channel::<(AlignedBuffer, u64)>(IN_FLIGHT);
        let (report, done) = std::sync::mpsc::channel();
        let queue = std::sync::Arc::new(std::sync::Mutex::new(queue));
        let mut threads = Vec::with_capacity(IN_FLIGHT);
        for _ in 0..IN_FLIGHT {
            let (file, queue, report) = (file.clone(), queue.clone(), report.clone());
            threads.push(
                std::thread::Builder::new()
                    .name("artifact-write".into())
                    .spawn(move || loop {
                        let job = queue.lock().map(|queue| queue.recv());
                        let Ok(Ok((buffer, offset))) = job else {
                            return;
                        };
                        use std::os::unix::fs::FileExt;
                        let result = file.write_all_at(buffer.get(), offset).map(|()| buffer);
                        if report.send(result).is_err() {
                            return;
                        }
                    })?,
            );
        }
        Ok(Self {
            jobs: Some(jobs),
            done,
            threads,
            in_flight: 0,
            allocated: 0,
            free: Vec::new(),
        })
    }

    /// An empty buffer, waiting for an earlier write when all are in flight.
    fn next_buffer(&mut self) -> io::Result<AlignedBuffer> {
        match self.free.pop() {
            Some(next) => Ok(next),
            None if self.allocated < IN_FLIGHT => {
                self.allocated += 1;
                Ok(AlignedBuffer::new())
            }
            None => self.wait(),
        }
    }

    /// Queue `buffer` for writing at `offset`.
    fn send(&mut self, buffer: AlignedBuffer, offset: u64) -> io::Result<()> {
        self.jobs
            .as_ref()
            .expect("live write pool")
            .send((buffer, offset))
            .map_err(|_| io::Error::other("artifact writer stopped"))?;
        self.in_flight += 1;
        Ok(())
    }

    fn wait(&mut self) -> io::Result<AlignedBuffer> {
        let result = self
            .done
            .recv()
            .map_err(|_| io::Error::other("artifact writer stopped"))?;
        self.in_flight -= 1;
        result
    }

    /// Wait for every queued write, reporting the first failure.
    fn drain(&mut self) -> io::Result<()> {
        let mut failure = None;
        while self.in_flight > 0 {
            match self.wait() {
                Ok(buffer) => self.free.push(buffer),
                Err(error) => failure = failure.or(Some(error)),
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(target_os = "linux")]
impl Drop for WritePool {
    fn drop(&mut self) {
        drop(self.jobs.take());
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) struct AlignedWriter {
    file: std::sync::Arc<File>,
    buffer: AlignedBuffer,
    used: usize,
    written: u64,
    direct: bool,
    pool: Option<WritePool>,
    /// A background write failed; every later call reports it.
    failed: Option<io::ErrorKind>,
}

impl ArtifactWriter {
    pub(crate) fn create(path: &Path, direct: bool) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        if direct {
            use std::os::unix::fs::OpenOptionsExt;
            match File::options()
                .write(true)
                .truncate(true)
                .create(true)
                .custom_flags(libc::O_DIRECT)
                .open(path)
            {
                Ok(file) => {
                    return Ok(Self::Aligned(AlignedWriter {
                        file: std::sync::Arc::new(file),
                        buffer: AlignedBuffer::new(),
                        used: 0,
                        written: 0,
                        direct: true,
                        pool: None,
                        failed: None,
                    }));
                }
                Err(error) if unsupported(&error) => {}
                Err(error) => return Err(error),
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = direct;
        Ok(Self::Buffered(File::create(path)?))
    }

    pub(crate) fn finish(self) -> io::Result<File> {
        match self {
            Self::Buffered(file) => Ok(file),
            #[cfg(target_os = "linux")]
            Self::Aligned(mut writer) => {
                writer.flush()?;
                drop(writer.pool.take());
                writer.file.set_len(writer.written + writer.used as u64)?;
                std::sync::Arc::try_unwrap(writer.file)
                    .map_err(|_| io::Error::other("artifact writer still in use"))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

impl Write for ArtifactWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Buffered(file) => file.write(bytes),
            #[cfg(target_os = "linux")]
            Self::Aligned(writer) => writer.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Buffered(file) => file.flush(),
            #[cfg(target_os = "linux")]
            Self::Aligned(writer) => writer.flush(),
        }
    }
}

#[cfg(target_os = "linux")]
impl AlignedWriter {
    fn check(&self) -> io::Result<()> {
        match self.failed {
            Some(kind) => Err(io::Error::new(kind, "an earlier artifact write failed")),
            None => Ok(()),
        }
    }

    fn poison<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if let Err(error) = &result {
            self.failed = Some(error.kind());
        }
        result
    }

    /// Write the buffer's used bytes, padded to alignment, at `written` and
    /// wait for it. Later writes overwrite the padding.
    fn write_tail(&mut self) -> io::Result<()> {
        use std::os::unix::fs::FileExt;
        let padded = self.used.div_ceil(ALIGN) * ALIGN;
        let bytes = &mut self.buffer.get_mut()[..padded];
        bytes[self.used..].fill(0);
        match self.file.write_all_at(bytes, self.written) {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.direct && self.written == 0 && unsupported(&error) {
                    use std::os::fd::AsRawFd;
                    // Some filesystems accept O_DIRECT on open but reject the
                    // first aligned write. No successful bytes are discarded.
                    let fd = self.file.as_raw_fd();
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    if flags < 0
                        || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_DIRECT) } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    self.direct = false;
                    return self.file.write_all_at(bytes, self.written);
                }
                Err(error)
            }
        }
    }

    /// Hand the full buffer to the write pool and continue in a fresh one.
    /// The first buffer is written in place so an unsupported direct write
    /// can still fall back before any bytes are queued.
    fn submit(&mut self) -> io::Result<()> {
        if self.written == 0 {
            self.write_tail()?;
        } else {
            if self.pool.is_none() {
                self.pool = Some(WritePool::spawn(&self.file)?);
            }
            let pool = self.pool.as_mut().expect("spawned above");
            let full = std::mem::replace(&mut self.buffer, pool.next_buffer()?);
            pool.send(full, self.written)?;
        }
        self.written += CAPACITY as u64;
        self.used = 0;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Write for AlignedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.check()?;
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.used == CAPACITY {
            let result = self.submit();
            self.poison(result)?;
        }
        let n = bytes.len().min(CAPACITY - self.used);
        let used = self.used;
        self.buffer.get_mut()[used..used + n].copy_from_slice(&bytes[..n]);
        self.used += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        let result = match self.pool.as_mut() {
            Some(pool) => pool.drain(),
            None => Ok(()),
        };
        self.poison(result)?;
        if self.used == 0 {
            return Ok(());
        }
        let result = self.write_tail();
        self.poison(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_writes_and_flushes_preserve_exact_bytes() {
        for direct in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("artifact");
            let mut writer = ArtifactWriter::create(&path, direct).unwrap();
            let mut expected = Vec::new();
            for n in [1, 4095, 7, CAPACITY + 19, 13, 0, 8191] {
                let bytes: Vec<_> = (0..n).map(|i| (i % 251) as u8).collect();
                writer.write_all(&bytes).unwrap();
                expected.extend_from_slice(&bytes);
                writer.flush().unwrap();
                writer.flush().unwrap();
            }
            writer.finish().unwrap().sync_all().unwrap();
            assert_eq!(std::fs::read(path).unwrap(), expected);
        }
    }

    #[test]
    fn concurrent_buffer_writes_preserve_order_and_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        let mut writer = ArtifactWriter::create(&path, true).unwrap();
        let mut expected = Vec::new();
        // Many full buffers in flight, odd-sized writes, and a flush midway.
        for round in 0..3_u32 {
            let bytes: Vec<_> = (0..(3 * CAPACITY + 12_345) as u32)
                .map(|i| (i.wrapping_mul(31).wrapping_add(round)) as u8)
                .collect();
            for chunk in bytes.chunks(1_000_003) {
                writer.write_all(chunk).unwrap();
            }
            expected.extend_from_slice(&bytes);
            if round == 1 {
                writer.flush().unwrap();
            }
        }
        writer.finish().unwrap().sync_all().unwrap();
        assert_eq!(std::fs::read(path).unwrap(), expected);
    }

    #[test]
    fn empty_artifact_stays_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty");
        let file = ArtifactWriter::create(&path, true)
            .unwrap()
            .finish()
            .unwrap();
        file.sync_all().unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
}
