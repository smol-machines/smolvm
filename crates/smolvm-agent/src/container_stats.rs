//! On-demand kernel accounting for Docker containers.

use smolvm_protocol::{error_codes, AgentResponse};

#[cfg(target_os = "linux")]
pub(crate) use accounting::configure;

pub(crate) fn handle(overlay_id: &str) -> AgentResponse {
    #[cfg(target_os = "linux")]
    {
        let Some(id) = crate::resolve_main_container(Some(overlay_id)) else {
            return AgentResponse::error("container is not running", error_codes::NOT_FOUND);
        };
        let Some(pid) = crate::crun_container_pid(&id) else {
            return AgentResponse::error("container is not running", error_codes::NOT_FOUND);
        };
        let result = accounting::path(&id).and_then(|path| {
            accounting::sample(&path, &format!("/proc/{pid}/net/dev"), "/proc/meminfo")
        });
        match result {
            Ok(usage) => AgentResponse::Ok {
                data: Some(serde_json::json!(usage)),
            },
            Err(error) => AgentResponse::error(
                format!("container accounting unavailable: {error}; restart the container with an updated guest"),
                error_codes::INTERNAL_ERROR,
            ),
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = overlay_id;
        AgentResponse::error(
            "container accounting requires Linux",
            error_codes::INTERNAL_ERROR,
        )
    }
}

#[cfg(any(target_os = "linux", test))]
mod accounting {
    use smolvm_protocol::{ContainerBlockIo, ContainerNetworkUsage, ContainerResourceUsage};
    use std::collections::BTreeMap;
    use std::io;
    use std::path::{Path, PathBuf};

    pub(super) fn path(id: &str) -> io::Result<PathBuf> {
        if id.is_empty()
            || !id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(invalid("invalid runtime container id"));
        }
        Ok(Path::new("/sys/fs/cgroup/smolvm/docker").join(id))
    }

    /// Every new Docker workload uses cgroupfs; a setup failure fails its start.
    /// No sampling worker or polling is needed: the kernel retains the counters.
    #[cfg(target_os = "linux")]
    pub(crate) fn configure(spec: &mut crate::oci::OciSpec, id: &str) -> io::Result<()> {
        let leaf = path(id)?;
        let root = Path::new("/sys/fs/cgroup");
        // Older runtime bundles mount the guest hierarchy read-only. Remount
        // this guest-local filesystem before creating the managed subtree.
        let target = c"/sys/fs/cgroup";
        let mut filesystem = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: target is NUL-terminated and filesystem is writable storage.
        if unsafe { libc::statvfs(target.as_ptr(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: statvfs initialized the structure on its successful return.
        let filesystem = unsafe { filesystem.assume_init() };
        if filesystem.f_flag & libc::ST_RDONLY != 0 {
            // SAFETY: this changes only the existing guest cgroup mount; a
            // remount accepts null source, filesystem type and data pointers.
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    target.as_ptr(),
                    std::ptr::null(),
                    libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                    std::ptr::null(),
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let required = ["cpu", "io", "memory", "pids"];
        let available = std::fs::read_to_string(root.join("cgroup.controllers"))?;
        if !required
            .iter()
            .all(|c| available.split_whitespace().any(|v| v == *c))
        {
            return Err(invalid(
                "guest kernel lacks CPU, I/O, memory or PID accounting",
            ));
        }
        for parent in [
            root.to_path_buf(),
            root.join("smolvm"),
            root.join("smolvm/docker"),
        ] {
            std::fs::create_dir_all(&parent)?;
            let control = parent.join("cgroup.subtree_control");
            let enabled = std::fs::read_to_string(&control)?;
            if !required
                .iter()
                .all(|c| enabled.split_whitespace().any(|v| v == *c))
            {
                std::fs::write(control, "+cpu +io +memory +pids")?;
            }
        }
        spec.linux.cgroups_path = Some(format!("/{}", leaf.strip_prefix(root).unwrap().display()));
        // A namespace keeps a workload's view rooted at its own cgroup while
        // retaining a writable subtree for systemd and nested container engines.
        if !spec.linux.namespaces.iter().any(|n| n.ns_type == "cgroup") {
            spec.linux.namespaces.push(crate::oci::OciNamespace {
                ns_type: "cgroup".into(),
                path: None,
            });
        }
        Ok(())
    }

    pub(super) fn sample(
        cgroup: &Path,
        network: &str,
        meminfo: &str,
    ) -> io::Result<ContainerResourceUsage> {
        let cpu_text = std::fs::read_to_string(cgroup.join("cpu.stat"))?;
        let memory_text = std::fs::read_to_string(cgroup.join("memory.stat"))?;
        let cpu = counters(&cpu_text)?;
        let memory = counters(&memory_text)?;
        let total = std::fs::read_to_string(meminfo)?;
        let guest_limit = total
            .lines()
            .find_map(|line| line.strip_prefix("MemTotal:"))
            .and_then(|value| value.split_whitespace().next())
            .ok_or_else(|| invalid("missing guest MemTotal"))?;
        let guest_limit = number(guest_limit)?.saturating_mul(1024);
        let limit = std::fs::read_to_string(cgroup.join("memory.max"))?;
        let memory_limit = if limit.trim() == "max" {
            guest_limit
        } else {
            number(limit.trim())?.min(guest_limit)
        };
        Ok(ContainerResourceUsage {
            cpu_usage_ns: required(&cpu, "usage_usec")?.saturating_mul(1000),
            cpu_user_ns: required(&cpu, "user_usec")?.saturating_mul(1000),
            cpu_system_ns: required(&cpu, "system_usec")?.saturating_mul(1000),
            cpu_periods: cpu.get("nr_periods").copied().unwrap_or(0),
            cpu_throttled_periods: cpu.get("nr_throttled").copied().unwrap_or(0),
            cpu_throttled_ns: cpu
                .get("throttled_usec")
                .copied()
                .unwrap_or(0)
                .saturating_mul(1000),
            memory_bytes: number(std::fs::read_to_string(cgroup.join("memory.current"))?.trim())?,
            memory_limit_bytes: memory_limit,
            inactive_file_bytes: required(&memory, "inactive_file")?,
            anonymous_bytes: required(&memory, "anon")?,
            file_bytes: required(&memory, "file")?,
            pids: number(std::fs::read_to_string(cgroup.join("pids.current"))?.trim())?,
            block_io: block_io(&std::fs::read_to_string(cgroup.join("io.stat"))?)?,
            networks: networks(&std::fs::read_to_string(network)?)?,
        })
    }

    fn invalid(message: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn number(value: &str) -> io::Result<u64> {
        value
            .parse()
            .map_err(|_| invalid("invalid kernel accounting counter"))
    }

    fn counters(text: &str) -> io::Result<BTreeMap<&str, u64>> {
        text.lines()
            .map(|line| {
                let mut fields = line.split_whitespace();
                let key = fields
                    .next()
                    .ok_or_else(|| invalid("missing counter name"))?;
                let value = fields
                    .next()
                    .ok_or_else(|| invalid("missing counter value"))?;
                Ok((key, number(value)?))
            })
            .collect()
    }

    fn required(counters: &BTreeMap<&str, u64>, key: &str) -> io::Result<u64> {
        counters
            .get(key)
            .copied()
            .ok_or_else(|| invalid(&format!("missing {key} counter")))
    }

    fn block_io(text: &str) -> io::Result<Vec<ContainerBlockIo>> {
        text.lines()
            .map(|line| {
                let mut fields = line.split_whitespace();
                let (major, minor) = fields
                    .next()
                    .and_then(|s| s.split_once(':'))
                    .ok_or_else(|| invalid("missing block device identity"))?;
                let mut values = BTreeMap::new();
                for field in fields {
                    let (key, value) = field
                        .split_once('=')
                        .ok_or_else(|| invalid("invalid block counter"))?;
                    values.insert(key, number(value)?);
                }
                Ok(ContainerBlockIo {
                    major: major.parse().map_err(|_| invalid("invalid device major"))?,
                    minor: minor.parse().map_err(|_| invalid("invalid device minor"))?,
                    read_bytes: required(&values, "rbytes")?,
                    write_bytes: required(&values, "wbytes")?,
                })
            })
            .collect()
    }

    fn networks(text: &str) -> io::Result<BTreeMap<String, ContainerNetworkUsage>> {
        let mut interfaces = BTreeMap::new();
        for line in text.lines() {
            let Some((name, values)) = line.rsplit_once(':') else {
                continue;
            };
            let name = name.trim();
            if name == "lo" {
                continue;
            }
            let values: Vec<u64> = values
                .split_whitespace()
                .map(number)
                .collect::<io::Result<_>>()?;
            if values.len() != 16 {
                return Err(invalid("incomplete network counters"));
            }
            interfaces.insert(
                name.to_owned(),
                ContainerNetworkUsage {
                    rx_bytes: values[0],
                    rx_packets: values[1],
                    rx_errors: values[2],
                    rx_dropped: values[3],
                    tx_bytes: values[8],
                    tx_packets: values[9],
                    tx_errors: values[10],
                    tx_dropped: values[11],
                },
            );
        }
        Ok(interfaces)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn fixture() -> tempfile::TempDir {
            let dir = tempfile::tempdir().unwrap();
            for (name, value) in [
                ("cpu.stat", "usage_usec 1200\nuser_usec 800\nsystem_usec 400\nnr_periods 3\nnr_throttled 1\nthrottled_usec 25\n"),
                ("memory.stat", "anon 65536\nfile 32768\ninactive_file 16384\n"),
                ("memory.current", "98304\n"), ("memory.max", "max\n"), ("pids.current", "7\n"),
                ("io.stat", "254:0 rbytes=4096 wbytes=8192 rios=1 wios=2\n254:16 rbytes=32 wbytes=64 rios=1 wios=1\n"),
                ("meminfo", "MemTotal: 262144 kB\n"),
                ("net", "Inter-| Receive | Transmit\n eth0: 10 11 12 13 14 15 16 17 20 21 22 23 24 25 26 27\n lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"),
            ] { std::fs::write(dir.path().join(name), value).unwrap(); }
            dir
        }

        fn read(dir: &Path) -> io::Result<ContainerResourceUsage> {
            sample(
                dir,
                dir.join("net").to_str().unwrap(),
                dir.join("meminfo").to_str().unwrap(),
            )
        }

        #[test]
        fn kernel_units_limits_devices_and_thread_counts_are_preserved() {
            let fixture = fixture();
            let result = read(fixture.path()).unwrap();
            assert_eq!(result.cpu_usage_ns, 1_200_000);
            assert_eq!(
                result.cpu_user_ns + result.cpu_system_ns,
                result.cpu_usage_ns
            );
            assert_eq!(result.cpu_throttled_ns, 25_000);
            assert_eq!(result.memory_limit_bytes, 256 << 20);
            assert_eq!(result.memory_bytes - result.inactive_file_bytes, 81920);
            assert_eq!(result.pids, 7);
            assert_eq!(result.block_io.len(), 2);
            assert_eq!(result.block_io[1].write_bytes, 64);
            assert_eq!(result.networks.len(), 1);
            assert_eq!(result.networks["eth0"].tx_dropped, 23);
            std::fs::write(fixture.path().join("memory.max"), "1048576").unwrap();
            assert_eq!(read(fixture.path()).unwrap().memory_limit_bytes, 1048576);
        }

        #[test]
        fn missing_or_invalid_accounting_is_not_reported_as_zero() {
            let fixture = fixture();
            std::fs::write(fixture.path().join("io.stat"), "").unwrap();
            assert!(read(fixture.path()).unwrap().block_io.is_empty());
            std::fs::write(fixture.path().join("cpu.stat"), "usage_usec broken\n").unwrap();
            assert!(read(fixture.path()).is_err());
            std::fs::remove_file(fixture.path().join("memory.current")).unwrap();
            assert!(read(fixture.path()).is_err());
            assert!(block_io("254:0 rios=1").is_err());
            assert!(networks("eth0: 1 2").is_err());
        }

        #[test]
        fn runtime_id_cannot_escape_the_accounting_tree() {
            for id in ["", "/", "..", "../pod", "x/y", "x\n"] {
                assert!(path(id).is_err());
            }
            assert_eq!(
                path("smolvm-123").unwrap(),
                Path::new("/sys/fs/cgroup/smolvm/docker/smolvm-123")
            );
        }
    }
}
