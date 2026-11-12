//! The reply exemption for legacy iptables (`x_tables`), the counterpart of
//! [`super::nft::add_exemption`] for workloads whose `iptables` is the legacy
//! one (Tailscale then installs its anti-spoofing rules there).
//!
//! For each legacy table in use in a namespace (`filter`, `raw`, `mangle`),
//! the built-in chains at prerouting and input get, first, the equivalent of
//! `-i lo -m conntrack --ctstate DNAT --ctdir REPLY -j ACCEPT`. The table is
//! read and written whole, the way `iptables -I` does it.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const TABLES: &[&str] = &["raw", "mangle", "filter"];
const XT_TABLE_MAXNAMELEN: usize = 32;
const NF_INET_NUMHOOKS: usize = 5;
const NF_INET_PRE_ROUTING: usize = 0;
const NF_INET_LOCAL_IN: usize = 1;
/// `IPT_SO_*` / `IP6T_SO_*`: the same numbers at `SOL_IP` / `SOL_IPV6`.
const SO_SET_REPLACE: libc::c_int = 64;
const SO_GET_INFO: libc::c_int = 64;
const SO_GET_ENTRIES: libc::c_int = 65;
const COUNTERS_LEN: usize = 16;
const XT_MATCH_HEADER: usize = 32;
const XT_TARGET_HEADER: usize = 32;
/// `xt_conntrack_mtinfo3`, padded to 8 bytes.
const CONNTRACK_INFO_LEN: usize = 168;
const XT_CONNTRACK_STATE: u16 = 1 << 0;
const XT_CONNTRACK_DIRECTION: u16 = 1 << 12;
/// `XT_CONNTRACK_STATE_DNAT`: `1 << (IP_CT_NUMBER + 2)`.
const XT_CONNTRACK_STATE_DNAT: u16 = 1 << 7;
/// `-NF_ACCEPT - 1`, a standard target's accept verdict.
const VERDICT_ACCEPT: i32 = -2;

#[derive(Clone, Copy, Debug)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub const ALL: [Family; 2] = [Family::V4, Family::V6];

    fn level(self) -> libc::c_int {
        match self {
            Family::V4 => libc::SOL_IP,
            Family::V6 => libc::SOL_IPV6,
        }
    }

    fn domain(self) -> libc::c_int {
        match self {
            Family::V4 => libc::AF_INET,
            Family::V6 => libc::AF_INET6,
        }
    }

    /// Tables in use in the calling thread's namespace.
    fn names_file(self) -> &'static str {
        match self {
            Family::V4 => "/proc/thread-self/net/ip_tables_names",
            Family::V6 => "/proc/thread-self/net/ip6_tables_names",
        }
    }

    /// Size of `ipt_ip` / `ip6t_ip6`, where an entry's own fields start.
    fn ip_len(self) -> usize {
        match self {
            Family::V4 => 84,
            Family::V6 => 136,
        }
    }

    /// Offset of the input interface name in `ipt_ip` / `ip6t_ip6`.
    fn iniface(self) -> usize {
        match self {
            Family::V4 => 16,
            Family::V6 => 64,
        }
    }

    /// Size of `ipt_entry` / `ip6t_entry`.
    fn entry_len(self) -> usize {
        match self {
            Family::V4 => 112,
            Family::V6 => 168,
        }
    }
}

/// Put the exemption first wherever a legacy table in this namespace hooks
/// prerouting or input; returns how many chains needed it.
pub fn ensure_exemptions() -> io::Result<usize> {
    let mut added = 0;
    for family in Family::ALL {
        let in_use = std::fs::read_to_string(family.names_file()).unwrap_or_default();
        for table in in_use.lines().filter(|name| TABLES.contains(name)) {
            added += ensure_in_table(family, table)?;
        }
    }
    Ok(added)
}

fn socket(family: Family) -> io::Result<OwnedFd> {
    // SAFETY: a raw socket only carries the x_tables socket options.
    let fd = unsafe {
        libc::socket(
            family.domain(),
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` was just created and is owned from here on.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// What `IPT_SO_GET_INFO` reports about a table.
struct Info {
    valid_hooks: u32,
    hook_entry: [u32; NF_INET_NUMHOOKS],
    underflow: [u32; NF_INET_NUMHOOKS],
    num_entries: u32,
    size: u32,
}

fn name_field(table: &str) -> [u8; XT_TABLE_MAXNAMELEN] {
    let mut name = [0u8; XT_TABLE_MAXNAMELEN];
    name[..table.len()].copy_from_slice(table.as_bytes());
    name
}

fn u32_at(buf: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn u16_at(buf: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes(buf[offset..offset + 2].try_into().unwrap())
}

fn get_info(socket: &OwnedFd, family: Family, table: &str) -> io::Result<Info> {
    // struct ipt_getinfo: name, valid_hooks, hook_entry[5], underflow[5],
    // num_entries, size.
    let mut buf = vec![0u8; XT_TABLE_MAXNAMELEN + 4 + 20 + 20 + 4 + 4];
    buf[..XT_TABLE_MAXNAMELEN].copy_from_slice(&name_field(table));
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: getsockopt into a buffer of the length passed.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            family.level(),
            SO_GET_INFO,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut info = Info {
        valid_hooks: u32_at(&buf, 32),
        hook_entry: [0; NF_INET_NUMHOOKS],
        underflow: [0; NF_INET_NUMHOOKS],
        num_entries: u32_at(&buf, 76),
        size: u32_at(&buf, 80),
    };
    for hook in 0..NF_INET_NUMHOOKS {
        info.hook_entry[hook] = u32_at(&buf, 36 + 4 * hook);
        info.underflow[hook] = u32_at(&buf, 56 + 4 * hook);
    }
    Ok(info)
}

fn get_entries(socket: &OwnedFd, family: Family, table: &str, size: u32) -> io::Result<Vec<u8>> {
    // struct ipt_get_entries: name, size, then the entries 8-byte aligned.
    const HEADER: usize = 40;
    let mut buf = vec![0u8; HEADER + size as usize];
    buf[..XT_TABLE_MAXNAMELEN].copy_from_slice(&name_field(table));
    buf[32..36].copy_from_slice(&size.to_ne_bytes());
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: getsockopt into a buffer of the length passed.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            family.level(),
            SO_GET_ENTRIES,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(buf.split_off(HEADER))
}

/// `-i lo -m conntrack --ctstate DNAT --ctdir REPLY -j ACCEPT`, counters zero.
pub fn exemption(family: Family) -> Vec<u8> {
    let match_len = XT_MATCH_HEADER + CONNTRACK_INFO_LEN;
    let target_len = XT_TARGET_HEADER + 8; // verdict, padded
    let entry_len = family.entry_len();
    let mut entry = vec![0u8; entry_len + match_len + target_len];
    // ip.iniface = "lo", ip.iniface_mask covers "lo\0".
    let iniface = family.iniface();
    entry[iniface..iniface + 2].copy_from_slice(b"lo");
    entry[iniface + 32..iniface + 35].fill(0xff);
    // target_offset and next_offset follow ip and nfcache.
    let offsets = family.ip_len() + 4;
    entry[offsets..offsets + 2].copy_from_slice(&((entry_len + match_len) as u16).to_ne_bytes());
    let total = entry.len() as u16;
    entry[offsets + 2..offsets + 4].copy_from_slice(&total.to_ne_bytes());
    // The conntrack match, revision 3.
    let m = entry_len;
    entry[m..m + 2].copy_from_slice(&(match_len as u16).to_ne_bytes());
    entry[m + 2..m + 2 + 9].copy_from_slice(b"conntrack");
    entry[m + 31] = 3;
    let info = m + XT_MATCH_HEADER;
    // After eight 16-byte addresses, expires_min/max and five u16 ports.
    let flags = info + 128 + 8 + 10;
    entry[flags..flags + 2]
        .copy_from_slice(&(XT_CONNTRACK_STATE | XT_CONNTRACK_DIRECTION).to_ne_bytes());
    // `--ctdir REPLY` is the direction match inverted.
    entry[flags + 2..flags + 4].copy_from_slice(&XT_CONNTRACK_DIRECTION.to_ne_bytes());
    entry[flags + 4..flags + 6].copy_from_slice(&XT_CONNTRACK_STATE_DNAT.to_ne_bytes());
    // The standard target (empty name) accepting.
    let t = entry_len + match_len;
    entry[t..t + 2].copy_from_slice(&(target_len as u16).to_ne_bytes());
    entry[t + XT_TARGET_HEADER..t + XT_TARGET_HEADER + 4]
        .copy_from_slice(&VERDICT_ACCEPT.to_ne_bytes());
    entry
}

/// An entry's bytes without its counters and bookkeeping, for comparison.
fn shape(family: Family, entry: &[u8]) -> Vec<u8> {
    let mut shape = entry.to_vec();
    let comefrom = family.ip_len() + 8;
    let counters_end = family.entry_len();
    if shape.len() >= counters_end {
        shape[comefrom..counters_end].fill(0);
    }
    shape
}

fn ensure_in_table(family: Family, table: &str) -> io::Result<usize> {
    let socket = socket(family)?;
    let info = get_info(&socket, family, table)?;
    let mut entries = get_entries(&socket, family, table, info.size)?;
    let ours = exemption(family);
    let mut info_out = Info {
        valid_hooks: info.valid_hooks,
        hook_entry: info.hook_entry,
        underflow: info.underflow,
        num_entries: info.num_entries,
        size: info.size,
    };
    let mut fixed = 0;
    for hook in [NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN] {
        if info_out.valid_hooks & (1 << hook) == 0 {
            continue;
        }
        let copies = copies_in_chain(family, &entries, &info_out, hook, &ours);
        let start = info_out.hook_entry[hook] as usize;
        if copies == [start] {
            continue;
        }
        // Another program put a rule before ours (`iptables -I`): move ours
        // back to the front rather than adding another.
        for &at in copies.iter().rev() {
            remove(family, &mut entries, &mut info_out, at, ours.len());
        }
        let start = info_out.hook_entry[hook] as usize;
        insert(family, &mut entries, &mut info_out, start, &ours);
        fixed += 1;
    }
    if fixed == 0 {
        return Ok(0);
    }
    replace(
        &socket,
        family,
        table,
        &info_out,
        info.num_entries,
        &entries,
    )?;
    Ok(fixed)
}

/// Offsets of the entries equal to `ours` in `hook`'s built-in chain.
fn copies_in_chain(
    family: Family,
    entries: &[u8],
    info: &Info,
    hook: usize,
    ours: &[u8],
) -> Vec<usize> {
    let mut copies = Vec::new();
    let mut at = info.hook_entry[hook] as usize;
    let end = info.underflow[hook] as usize;
    let want = shape(family, ours);
    while at < end && at + family.entry_len() <= entries.len() {
        let next = u16_at(entries, at + family.ip_len() + 6) as usize;
        if next == 0 {
            break;
        }
        if next == ours.len() && shape(family, &entries[at..at + next]) == want {
            copies.push(at);
        }
        at += next;
    }
    copies
}

/// Remove the `len`-byte entry at `at`, moving every hook, underflow and
/// jump past it back.
fn remove(family: Family, entries: &mut Vec<u8>, info: &mut Info, at: usize, len: usize) {
    entries.drain(at..at + len);
    adjust_jumps(family, entries, |offset| {
        (offset > at).then(|| offset - len)
    });
    for hook in 0..NF_INET_NUMHOOKS {
        if info.valid_hooks & (1 << hook) == 0 {
            continue;
        }
        if info.hook_entry[hook] as usize > at {
            info.hook_entry[hook] -= len as u32;
        }
        if info.underflow[hook] as usize > at {
            info.underflow[hook] -= len as u32;
        }
    }
    info.num_entries -= 1;
    info.size -= len as u32;
}

/// Rewrite every jump (a standard target whose verdict is an offset) that
/// `map` moves.
fn adjust_jumps(family: Family, entries: &mut [u8], map: impl Fn(usize) -> Option<usize>) {
    let mut offset = 0;
    while offset + family.entry_len() <= entries.len() {
        let target_offset = u16_at(entries, offset + family.ip_len() + 4) as usize;
        let next_offset = u16_at(entries, offset + family.ip_len() + 6) as usize;
        if next_offset == 0 {
            break;
        }
        let target = offset + target_offset;
        let is_standard = entries[target + 2] == 0;
        let target_size = u16_at(entries, target) as usize;
        if is_standard && target_size >= XT_TARGET_HEADER + 4 {
            let verdict_at = target + XT_TARGET_HEADER;
            let verdict =
                i32::from_ne_bytes(entries[verdict_at..verdict_at + 4].try_into().unwrap());
            if verdict >= 0 {
                if let Some(moved) = map(verdict as usize) {
                    entries[verdict_at..verdict_at + 4]
                        .copy_from_slice(&(moved as i32).to_ne_bytes());
                }
            }
        }
        offset += next_offset;
    }
}

/// Insert `entry` at offset `at`, moving every hook, underflow and jump at or
/// past it.
fn insert(family: Family, entries: &mut Vec<u8>, info: &mut Info, at: usize, entry: &[u8]) {
    let grow = entry.len();
    adjust_jumps(family, entries, |offset| {
        (offset >= at).then(|| offset + grow)
    });
    for hook in 0..NF_INET_NUMHOOKS {
        if info.valid_hooks & (1 << hook) == 0 {
            continue;
        }
        // The chain the entry starts keeps pointing at it.
        if info.hook_entry[hook] as usize > at {
            info.hook_entry[hook] += grow as u32;
        }
        if info.underflow[hook] as usize >= at {
            info.underflow[hook] += grow as u32;
        }
    }
    entries.splice(at..at, entry.iter().copied());
    info.num_entries += 1;
    info.size += grow as u32;
}

fn replace(
    socket: &OwnedFd,
    family: Family,
    table: &str,
    info: &Info,
    old_entries: u32,
    entries: &[u8],
) -> io::Result<()> {
    // struct ipt_replace: name, valid_hooks, num_entries, size,
    // hook_entry[5], underflow[5], num_counters, counters pointer, then the
    // entries 8-byte aligned.
    const HEADER: usize = 96;
    let mut counters = vec![0u8; old_entries as usize * COUNTERS_LEN];
    let mut buf = vec![0u8; HEADER + entries.len()];
    buf[..32].copy_from_slice(&name_field(table));
    buf[32..36].copy_from_slice(&info.valid_hooks.to_ne_bytes());
    buf[36..40].copy_from_slice(&info.num_entries.to_ne_bytes());
    buf[40..44].copy_from_slice(&info.size.to_ne_bytes());
    for hook in 0..NF_INET_NUMHOOKS {
        buf[44 + 4 * hook..48 + 4 * hook].copy_from_slice(&info.hook_entry[hook].to_ne_bytes());
        buf[64 + 4 * hook..68 + 4 * hook].copy_from_slice(&info.underflow[hook].to_ne_bytes());
    }
    buf[84..88].copy_from_slice(&old_entries.to_ne_bytes());
    buf[88..96].copy_from_slice(&(counters.as_mut_ptr() as u64).to_ne_bytes());
    buf[HEADER..].copy_from_slice(entries);
    // SAFETY: setsockopt from a buffer of the length passed; the counters
    // buffer it points at outlives the call.
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            family.level(),
            SO_SET_REPLACE,
            buf.as_ptr().cast(),
            buf.len() as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_exemption_is_one_well_formed_entry() {
        for family in Family::ALL {
            let entry = exemption(family);
            assert_eq!(entry.len() % 8, 0);
            let target_offset = u16_at(&entry, family.ip_len() + 4) as usize;
            let next_offset = u16_at(&entry, family.ip_len() + 6) as usize;
            assert_eq!(next_offset, entry.len());
            assert_eq!(
                &entry[family.entry_len() + 2..family.entry_len() + 11],
                b"conntrack"
            );
            assert_eq!(
                i32::from_ne_bytes(
                    entry[target_offset + 32..target_offset + 36]
                        .try_into()
                        .unwrap()
                ),
                VERDICT_ACCEPT
            );
        }
    }

    #[test]
    fn inserting_moves_later_hooks_underflows_and_jumps() {
        let family = Family::V4;
        // Two entries: a jump to offset `second` at the chain start, then a
        // standard accept that is the chain's underflow.
        let mut first = exemption(family);
        let second = first.len();
        let t = u16_at(&first, family.ip_len() + 4) as usize;
        first[t + 32..t + 36].copy_from_slice(&(second as i32).to_ne_bytes());
        let mut entries = first.clone();
        entries.extend(exemption(family));
        let mut info = Info {
            valid_hooks: 1 << NF_INET_LOCAL_IN,
            hook_entry: [0; 5],
            underflow: [0, second as u32, 0, 0, 0],
            num_entries: 2,
            size: entries.len() as u32,
        };
        let ours = exemption(family);
        insert(family, &mut entries, &mut info, 0, &ours);
        assert_eq!(info.hook_entry[NF_INET_LOCAL_IN], 0);
        assert_eq!(
            info.underflow[NF_INET_LOCAL_IN] as usize,
            second + ours.len()
        );
        let jump_at = ours.len() + t + 32;
        assert_eq!(
            i32::from_ne_bytes(entries[jump_at..jump_at + 4].try_into().unwrap()) as usize,
            second + ours.len()
        );
        assert_eq!(info.num_entries, 3);
    }
}
