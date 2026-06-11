//! Linux network configuration helpers for a given host NIC.

use std::net::{Ipv4Addr, Ipv6Addr};

/// `IFA_F_NODAD` from `linux/if_addr.h`: skip Duplicate Address Detection for a
/// statically assigned IPv6 address. On the two-node virtual link the addresses
/// are deterministic, and skipping DAD avoids the ~1s "tentative" window before
/// the guest can use its IPv6 address.
const IFA_F_NODAD: u8 = 0x02;

/// Configure a guest interface for the virtio-net.
///
/// High-level flow:
///
/// ```text
/// 1. find eth0's ifindex                 (SIOCGIFINDEX)
/// 2. set link-layer MAC address          (SIOCSIFHWADDR)
/// 3. set MTU                             (SIOCSIFMTU)
/// 4. add IPv4 address/prefix             (RTM_NEWADDR via NETLINK_ROUTE)
/// 5. mark the interface UP               (SIOCGIFFLAGS + SIOCSIFFLAGS)
/// 6. add the default route               (RTM_NEWROUTE via NETLINK_ROUTE)
/// 7. write /etc/resolv.conf              (plain file write)
/// ```
///
/// Read these functions as:
///
/// ```text
/// set_mac_address()   ~= ip link set dev eth0 address ...
/// set_mtu()           ~= ip link set dev eth0 mtu ...
/// add_address_v4()    ~= ip addr add ...
/// bring_interface_up()~= ip link set dev eth0 up
/// add_default_route() ~= ip route add default via ...
/// ```
///
/// Outcome:
/// - the guest ends up with a configured `eth0`
/// - traffic to non-local destinations is sent to `gateway`
/// - libc DNS resolution uses `dns_server`
///
/// Why this order:
/// - MAC and MTU are link attributes, so we set them before bringing the
///   interface fully up
/// - the IPv4 address and route are programmed explicitly instead of relying on
///   DHCP or helper tools
/// - the function is fail-fast: any kernel call failure aborts boot for the
///   requested virtio-net path
/// - the address is installed before the route so the kernel already knows the
///   guest's on-link subnet when the default gateway is added
///
/// The Linux kernel interfaces used here are all C ABI calls:
///
/// - `SIOCGIFINDEX`: asks the kernel for the numeric interface index for
///   `ifname`. Netlink messages use that numeric id, not the human-readable
///   string.
/// - `SIOCSIFHWADDR`: updates the NIC MAC address.
/// - `SIOCSIFMTU`: updates the NIC MTU.
/// - `SIOCGIFFLAGS` / `SIOCSIFFLAGS`: read-modify-write the interface flags so
///   we can set `IFF_UP`.
/// - `RTM_NEWADDR`: asks the kernel routing stack to add an IPv4 address.
/// - `RTM_NEWROUTE`: asks the kernel routing stack to install the default route.
#[allow(clippy::too_many_arguments)]
pub fn configure_interface(
    ifname: &str,
    mac: [u8; 6],
    mtu: u16,
    address: Ipv4Addr,
    prefix_len: u8,
    gateway: Ipv4Addr,
    ipv6: Option<(Ipv6Addr, u8, Ipv6Addr)>,
    dns_server: Ipv4Addr,
) -> Result<(), String> {
    let ifindex = get_ifindex(ifname)?;
    set_mac_address(ifname, &mac)?;
    set_mtu(ifname, mtu)?;
    add_address_v4(ifindex, address, prefix_len)?;
    bring_interface_up(ifname)?;
    add_default_route_v4(gateway)?;
    if let Some((address6, prefix_len6, gateway6)) = ipv6 {
        add_address_v6(ifindex, address6, prefix_len6)?;
        add_default_route_v6(gateway6)?;
    }
    write_resolv_conf(dns_server)?;
    Ok(())
}

/// Resolve the Linux interface index used by rtnetlink messages.
///
/// C ABI context:
/// - opens an `AF_INET` datagram socket only as an ioctl handle
/// - fills an `ifreq`
/// - calls `ioctl(..., SIOCGIFINDEX, ...)`
///
/// Usage:
/// - `ifname` is the human-readable name, such as `eth0`
///
/// Outcome:
/// - returns the kernel's numeric interface id, which is later embedded into
///   `RTM_NEWADDR`
///
/// Why this exists:
/// - `ioctl` interface operations identify the device by name in `ifreq`
/// - rtnetlink address operations identify the device by numeric index
/// - this is the bridge between those two APIs
fn get_ifindex(ifname: &str) -> Result<u32, String> {
    // SAFETY: `ifreq` is plain old data; zeroed initialization is valid.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr, ifname)?;

        let sock = socket_fd()?;
        if libc::ioctl(sock, libc::SIOCGIFINDEX as _, &mut ifr) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCGIFINDEX failed for {}: {}", ifname, err));
        }
        libc::close(sock);

        Ok(ifr.ifr_ifru.ifru_ifindex as u32)
    }
}

/// Program the NIC MAC address with `SIOCSIFHWADDR`.
///
/// C ABI context:
/// - `ifreq.ifru_hwaddr` carries a `sockaddr`-shaped payload
/// - `sa_family = ARPHRD_ETHER` tells the kernel the address is Ethernet
/// - the first 6 bytes of `sa_data` hold the MAC octets
///
/// Outcome:
/// - future packets emitted by this guest NIC use the requested source MAC
///
/// Shell equivalent:
///
/// ```text
/// ip link set dev <ifname> address <mac>
/// ```
fn set_mac_address(ifname: &str, mac: &[u8; 6]) -> Result<(), String> {
    // SAFETY: `ifreq` is plain old data; zeroed initialization is valid.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr, ifname)?;

        ifr.ifr_ifru.ifru_hwaddr.sa_family = libc::ARPHRD_ETHER;
        ifr.ifr_ifru.ifru_hwaddr.sa_data[..6]
            .copy_from_slice(&mac.map(|byte| byte as libc::c_char));

        let sock = socket_fd()?;
        if libc::ioctl(sock, libc::SIOCSIFHWADDR as _, &ifr) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFHWADDR failed for {}: {}", ifname, err));
        }
        libc::close(sock);
    }
    Ok(())
}

/// Program the link MTU with `SIOCSIFMTU`.
///
/// C ABI context:
/// - `ifreq.ifru_mtu` is interpreted by the kernel as the requested MTU value
///
/// Outcome:
/// - the kernel enforces this frame size for the interface
///
/// Shell equivalent:
///
/// ```text
/// ip link set dev <ifname> mtu <mtu>
/// ```
fn set_mtu(ifname: &str, mtu: u16) -> Result<(), String> {
    // SAFETY: `ifreq` is plain old data; zeroed initialization is valid.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr, ifname)?;
        ifr.ifr_ifru.ifru_mtu = mtu as libc::c_int;

        let sock = socket_fd()?;
        if libc::ioctl(sock, libc::SIOCSIFMTU as _, &ifr) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFMTU failed for {}: {}", ifname, err));
        }
        libc::close(sock);
    }
    Ok(())
}

/// Mark the interface `IFF_UP`.
///
/// C ABI context:
/// - `SIOCGIFFLAGS` reads the current flag word
/// - we OR in `IFF_UP`
/// - `SIOCSIFFLAGS` writes the updated flag word back
///
/// Outcome:
/// - the kernel considers the interface administratively up and will start
///   using the configured address and route
///
/// Shell equivalent:
///
/// ```text
/// ip link set dev <ifname> up
/// ```
fn bring_interface_up(ifname: &str) -> Result<(), String> {
    // SAFETY: `ifreq` is plain old data; zeroed initialization is valid.
    unsafe {
        let mut ifr: libc::ifreq = std::mem::zeroed();
        copy_ifname(&mut ifr, ifname)?;

        let sock = socket_fd()?;
        if libc::ioctl(sock, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCGIFFLAGS failed for {}: {}", ifname, err));
        }

        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
        if libc::ioctl(sock, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(format!("SIOCSIFFLAGS failed for {}: {}", ifname, err));
        }
        libc::close(sock);
    }
    Ok(())
}

/// Add the guest IPv4 address through rtnetlink.
///
/// This is the programmatic equivalent of:
///
/// ```text
/// ip addr add <address>/<prefix_len> dev <ifname>
/// ```
///
/// Outcome:
/// - the kernel records the IPv4 address on the interface identified by
///   `ifindex`
///
/// Why netlink here:
/// - there is no classic `ioctl` that cleanly expresses modern address
///   creation the way `ip addr add` does
/// - rtnetlink is the kernel's structured control plane for addresses and
///   routes
fn add_address_v4(ifindex: u32, address: Ipv4Addr, prefix_len: u8) -> Result<(), String> {
    let address_bytes = address.octets();
    netlink_newaddr(ifindex, libc::AF_INET as u8, 0, prefix_len, &address_bytes).map_err(|err| {
        format!(
            "failed to add IPv4 address {}/{}: {}",
            address, prefix_len, err
        )
    })
}

/// Add the guest IPv6 address through rtnetlink (`ip -6 addr add ...`), with
/// DAD skipped (see [`IFA_F_NODAD`]).
fn add_address_v6(ifindex: u32, address: Ipv6Addr, prefix_len: u8) -> Result<(), String> {
    let address_bytes = address.octets();
    netlink_newaddr(
        ifindex,
        libc::AF_INET6 as u8,
        IFA_F_NODAD,
        prefix_len,
        &address_bytes,
    )
    .map_err(|err| {
        format!(
            "failed to add IPv6 address {}/{}: {}",
            address, prefix_len, err
        )
    })
}

/// Install the default IPv4 route through the provided gateway.
///
/// This is the programmatic equivalent of:
///
/// ```text
/// ip route add default via <gateway>
/// ```
///
/// Outcome:
/// - traffic for non-local destinations is sent to `gateway`
///
/// Why only a gateway attribute is needed here:
/// - the default route says "for destinations not matched by a more specific
///   route, send to this next hop"
/// - because the guest interface address was installed first, the kernel can
///   resolve that gateway as reachable on the connected subnet
fn add_default_route_v4(gateway: Ipv4Addr) -> Result<(), String> {
    let gateway_bytes = gateway.octets();
    netlink_newroute(libc::AF_INET as u8, &gateway_bytes)
        .map_err(|err| format!("failed to add default route via {}: {}", gateway, err))
}

/// Install the default IPv6 route through the provided gateway
/// (`ip -6 route add default via ...`).
fn add_default_route_v6(gateway: Ipv6Addr) -> Result<(), String> {
    let gateway_bytes = gateway.octets();
    netlink_newroute(libc::AF_INET6 as u8, &gateway_bytes)
        .map_err(|err| format!("failed to add default IPv6 route via {}: {}", gateway, err))
}

/// Replace `/etc/resolv.conf` with the gateway-side resolver.
///
/// Outcome:
/// - standard guest libc resolution (`getaddrinfo`, `nslookup`, etc.) sends DNS
///   traffic to the host-provided resolver path
///
/// This step is intentionally plain file I/O rather than a C networking API.
/// DNS configuration in a minimal Linux guest is usually conveyed through
/// `/etc/resolv.conf`, and that is enough for the MVP.
fn write_resolv_conf(dns_server: Ipv4Addr) -> Result<(), String> {
    let contents = format!("nameserver {}\n", dns_server);
    let direct_err = match std::fs::write("/etc/resolv.conf", &contents) {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };

    // Read-only /etc (the Linux agent rootfs boots read-only — same trap class
    // as the read-only /tmp): stage the file on the tmpfs /tmp and bind-mount
    // it over /etc/resolv.conf. And in NO case may DNS config kill the boot —
    // the interface, routes, and egress NAT are already up; a guest without
    // resolv.conf still serves published ports and numeric egress — so any
    // residual failure degrades to a WARN instead of an Err (which the caller
    // treats as fatal for PID 1).
    let staged = "/tmp/.smolvm-resolv.conf";
    if let Err(e) = std::fs::write(staged, &contents) {
        tracing::warn!(error = %e, original = %direct_err,
            "resolv.conf unwritable and tmpfs staging failed; continuing without DNS config");
        return Ok(());
    }
    let src = std::ffi::CString::new(staged).expect("static path");
    let dst = std::ffi::CString::new("/etc/resolv.conf").expect("static path");
    let rc = unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        tracing::warn!(
            error = %std::io::Error::last_os_error(),
            original = %direct_err,
            "resolv.conf bind-mount fallback failed; continuing without DNS config"
        );
    }
    Ok(())
}

/// Create a datagram socket used only as an ioctl control handle.
///
/// C ABI context:
/// - many legacy interface ioctls operate on any socket fd from the right
///   address family
/// - this socket is not used for packet I/O
///
/// Outcome:
/// - returns an fd suitable for `SIOCGIFINDEX`, `SIOCSIFHWADDR`,
///   `SIOCSIFMTU`, and `SIOCSIFFLAGS`
///
/// Important distinction:
/// - this is not the data path for guest traffic
/// - it is just a capability handle the kernel accepts for network ioctls
fn socket_fd() -> Result<libc::c_int, String> {
    // SAFETY: `socket` is a standard libc call with valid arguments.
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(format!(
            "failed to create socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(fd)
}

/// Copy an interface name into `ifreq.ifr_name`.
///
/// C ABI context:
/// - most interface ioctls use `ifreq`
/// - the kernel matches the request to an interface through the fixed-width
///   `ifr_name` buffer
/// - `ifreq` was zero-initialized, so copying only the visible bytes leaves the
///   trailing NUL padding in place
fn copy_ifname(ifr: &mut libc::ifreq, ifname: &str) -> Result<(), String> {
    let bytes = ifname.as_bytes();
    if bytes.len() >= libc::IFNAMSIZ {
        return Err(format!("interface name too long: {}", ifname));
    }

    // SAFETY: `ifr_name` is large enough because of the length check above.
    unsafe {
        std::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            ifr.ifr_name.as_mut_ptr().cast(),
            bytes.len(),
        );
    }

    Ok(())
}

/// Minimal Linux `ifaddrmsg` layout used by `RTM_NEWADDR`.
///
/// We define the struct locally instead of relying on higher-level helpers so
/// the agent stays self-contained in the guest environment.
///
/// Meaning of the fields we populate:
/// - `ifa_family = AF_INET`: this is an IPv4 address operation
/// - `ifa_prefixlen`: subnet length, for example `24`
/// - `ifa_scope = RT_SCOPE_UNIVERSE`: globally scoped address, not host-local
/// - `ifa_index`: target interface id returned by `SIOCGIFINDEX`
#[repr(C)]
struct IfAddrMsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: u32,
}

/// Minimal Linux `rtmsg` layout used by `RTM_NEWROUTE`.
///
/// Meaning of the fields we populate:
/// - `rtm_family = AF_INET`: this is an IPv4 route
/// - `rtm_dst_len = 0`: zero-bit destination prefix, which means "default route"
/// - `rtm_table = RT_TABLE_MAIN`: install into the main routing table
/// - `rtm_protocol = RTPROT_BOOT`: route was installed during boot/runtime init
/// - `rtm_scope = RT_SCOPE_UNIVERSE`: globally reachable route
/// - `rtm_type = RTN_UNICAST`: normal unicast forwarding entry
#[repr(C)]
struct RtMsg {
    rtm_family: u8,
    rtm_dst_len: u8,
    rtm_src_len: u8,
    rtm_tos: u8,
    rtm_table: u8,
    rtm_protocol: u8,
    rtm_scope: u8,
    rtm_type: u8,
    rtm_flags: u32,
}

const NLMSG_HDRLEN: usize = 16;
const IFADDRMSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const RTA_HDRLEN: usize = 4;

const _: () = assert!(std::mem::size_of::<libc::nlmsghdr>() == NLMSG_HDRLEN);
const _: () = assert!(std::mem::size_of::<IfAddrMsg>() == IFADDRMSG_LEN);
const _: () = assert!(std::mem::size_of::<RtMsg>() == RTMSG_LEN);

/// Build and send an `RTM_NEWADDR` netlink message.
///
/// C ABI context:
/// - `nlmsghdr` is the outer netlink envelope
/// - `IfAddrMsg` is the `RTM_NEWADDR` body
/// - `IFA_ADDRESS` and `IFA_LOCAL` are route attributes appended after the body
///
/// Outcome:
/// - asks the kernel to attach an IPv4 address/prefix to `ifindex`
///
/// Message shape:
///
/// ```text
/// nlmsghdr
///   type  = RTM_NEWADDR
///   flags = REQUEST | ACK | CREATE | EXCL
/// ifaddrmsg
///   family    = AF_INET
///   prefixlen = <prefix_len>
///   index     = <ifindex>
/// rtattr IFA_ADDRESS = <IPv4 bytes>
/// rtattr IFA_LOCAL   = <IPv4 bytes>
/// ```
///
/// Why both `IFA_ADDRESS` and `IFA_LOCAL` are present:
/// - for a plain unicast interface address, both effectively describe the same
///   address
/// - including both matches the common shape produced by tools like `ip`
///   for local interface address assignment
///
/// `family` selects IPv4 (`AF_INET`, 4-byte address) or IPv6 (`AF_INET6`,
/// 16-byte address); `flags` carries e.g. [`IFA_F_NODAD`].
fn netlink_newaddr(
    ifindex: u32,
    family: u8,
    flags: u8,
    prefix_len: u8,
    address: &[u8],
) -> std::io::Result<()> {
    let rta_len = rta_space(address.len());
    let msg_len = NLMSG_HDRLEN + IFADDRMSG_LEN + (rta_len * 2);
    let mut buf = vec![0u8; nlmsg_align(msg_len)];

    let nlh = buf.as_mut_ptr().cast::<libc::nlmsghdr>();
    // SAFETY: `buf` is large enough for `nlmsghdr`.
    unsafe {
        (*nlh).nlmsg_len = msg_len as u32;
        (*nlh).nlmsg_type = libc::RTM_NEWADDR;
        (*nlh).nlmsg_flags =
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
        (*nlh).nlmsg_seq = 1;
    }

    let ifa = unsafe { buf.as_mut_ptr().add(NLMSG_HDRLEN).cast::<IfAddrMsg>() };
    // SAFETY: `buf` is large enough for `IfAddrMsg`.
    unsafe {
        (*ifa).ifa_family = family;
        (*ifa).ifa_prefixlen = prefix_len;
        (*ifa).ifa_flags = flags;
        (*ifa).ifa_scope = libc::RT_SCOPE_UNIVERSE;
        (*ifa).ifa_index = ifindex;
    }

    let mut offset = NLMSG_HDRLEN + IFADDRMSG_LEN;
    write_rta(&mut buf[offset..], libc::IFA_ADDRESS, address);
    offset += rta_space(address.len());
    write_rta(&mut buf[offset..], libc::IFA_LOCAL, address);

    netlink_send(&buf)
}

/// Build and send an `RTM_NEWROUTE` netlink message for the default route.
///
/// C ABI context:
/// - `rtm_dst_len = 0` means "default route"
/// - `RTA_GATEWAY` carries the next-hop IPv4 address
///
/// Outcome:
/// - asks the kernel to install a unicast route in the main table
///
/// Message shape:
///
/// ```text
/// nlmsghdr
///   type  = RTM_NEWROUTE
///   flags = REQUEST | ACK | CREATE | EXCL
/// rtmsg
///   family   = AF_INET
///   dst_len  = 0
///   table    = RT_TABLE_MAIN
///   protocol = RTPROT_BOOT
///   scope    = RT_SCOPE_UNIVERSE
///   type     = RTN_UNICAST
/// rtattr RTA_GATEWAY = <gateway address bytes>
/// ```
///
/// `family` selects IPv4 (`AF_INET`, 4-byte gateway) or IPv6 (`AF_INET6`,
/// 16-byte gateway).
fn netlink_newroute(family: u8, gateway: &[u8]) -> std::io::Result<()> {
    let rta_len = rta_space(gateway.len());
    let msg_len = NLMSG_HDRLEN + RTMSG_LEN + rta_len;
    let mut buf = vec![0u8; nlmsg_align(msg_len)];

    let nlh = buf.as_mut_ptr().cast::<libc::nlmsghdr>();
    // SAFETY: `buf` is large enough for `nlmsghdr`.
    unsafe {
        (*nlh).nlmsg_len = msg_len as u32;
        (*nlh).nlmsg_type = libc::RTM_NEWROUTE;
        (*nlh).nlmsg_flags =
            (libc::NLM_F_REQUEST | libc::NLM_F_ACK | libc::NLM_F_CREATE | libc::NLM_F_EXCL) as u16;
        (*nlh).nlmsg_seq = 2;
    }

    let rtm = unsafe { buf.as_mut_ptr().add(NLMSG_HDRLEN).cast::<RtMsg>() };
    // SAFETY: `buf` is large enough for `RtMsg`.
    unsafe {
        (*rtm).rtm_family = family;
        (*rtm).rtm_dst_len = 0;
        (*rtm).rtm_src_len = 0;
        (*rtm).rtm_tos = 0;
        (*rtm).rtm_table = libc::RT_TABLE_MAIN;
        (*rtm).rtm_protocol = libc::RTPROT_BOOT;
        (*rtm).rtm_scope = libc::RT_SCOPE_UNIVERSE;
        (*rtm).rtm_type = libc::RTN_UNICAST;
        (*rtm).rtm_flags = 0;
    }

    let offset = NLMSG_HDRLEN + RTMSG_LEN;
    write_rta(&mut buf[offset..], libc::RTA_GATEWAY, gateway);
    netlink_send(&buf)
}

/// Send one netlink request and wait for the kernel ack.
///
/// Walkthrough:
///
/// ```text
/// userspace buffer
///   -> socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)
///   -> bind(local netlink sockaddr)
///   -> send(message)
///   -> recv(ack)
///   -> inspect NLMSG_ERROR
/// ```
///
/// C ABI context:
/// - `socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)` opens a routing netlink
///   endpoint to the kernel
/// - `bind` attaches a local netlink address so the kernel can reply
/// - `send` transmits the prepared `nlmsghdr + payload`
/// - `recv` collects the kernel ack
/// - the ack payload for `NLMSG_ERROR` contains a signed errno:
///   - `0` means success
///   - a negative errno means failure
///
/// Outcome:
/// - returns `Ok(())` once the kernel accepts the request
/// - returns an `io::Error` if socket creation, send/recv, or the kernel ack
///   reports a failure
///
/// Important distinction from the virtio-net data path:
/// - this socket is not carrying guest Ethernet traffic
/// - it is a control-plane socket used only to ask the Linux kernel to mutate
///   routing/address state inside the guest
fn netlink_send(msg: &[u8]) -> std::io::Result<()> {
    // SAFETY: all libc calls use valid buffers and checked lengths.
    unsafe {
        let sock = libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, libc::NETLINK_ROUTE);
        if sock < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut sockaddr: libc::sockaddr_nl = std::mem::zeroed();
        sockaddr.nl_family = libc::AF_NETLINK as u16;
        if libc::bind(
            sock,
            (&sockaddr as *const libc::sockaddr_nl).cast(),
            std::mem::size_of::<libc::sockaddr_nl>() as u32,
        ) < 0
        {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(err);
        }

        if libc::send(sock, msg.as_ptr().cast(), msg.len(), 0) < 0 {
            let err = std::io::Error::last_os_error();
            libc::close(sock);
            return Err(err);
        }

        let mut ack = [0u8; 1024];
        let bytes = libc::recv(sock, ack.as_mut_ptr().cast(), ack.len(), 0);
        libc::close(sock);
        if bytes < 0 {
            return Err(std::io::Error::last_os_error());
        }

        if (bytes as usize) >= NLMSG_HDRLEN + 4 {
            let nlh = ack.as_ptr().cast::<libc::nlmsghdr>();
            if (*nlh).nlmsg_type == libc::NLMSG_ERROR as u16 {
                let err =
                    i32::from_ne_bytes(ack[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into().unwrap());
                if err < 0 {
                    return Err(std::io::Error::from_raw_os_error(-err));
                }
            }
        }

        Ok(())
    }
}

/// Netlink/rtnetlink attributes are 4-byte aligned.
///
/// The kernel expects both message bodies and nested attributes to start on
/// 4-byte boundaries. This helper rounds a length up to that alignment.
fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Space consumed by one route attribute including alignment padding.
///
/// An `rtattr` is:
///
/// ```text
/// [u16 len][u16 type][payload bytes][optional padding]
/// ```
///
/// `rta_space` returns the full reserved byte count, not just the visible
/// header + payload.
fn rta_space(data_len: usize) -> usize {
    nlmsg_align(RTA_HDRLEN + data_len)
}

/// Encode one `rtattr` header plus its payload bytes into `buf`.
///
/// `buf` is expected to be large enough for `rta_space(data.len())`. The caller
/// is responsible for advancing the offset by the aligned size so the next
/// attribute starts on a 4-byte boundary.
fn write_rta(buf: &mut [u8], rta_type: u16, data: &[u8]) {
    let rta_len = (RTA_HDRLEN + data.len()) as u16;
    buf[0..2].copy_from_slice(&rta_len.to_ne_bytes());
    buf[2..4].copy_from_slice(&rta_type.to_ne_bytes());
    buf[RTA_HDRLEN..RTA_HDRLEN + data.len()].copy_from_slice(data);
}
