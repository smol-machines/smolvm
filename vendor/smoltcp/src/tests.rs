use std::collections::VecDeque;

use crate::iface::*;
use crate::phy::{self, Device, DeviceCapabilities, Medium};
use crate::time::Instant;
use crate::wire::*;

pub(crate) fn setup<'a>(medium: Medium) -> (Interface, SocketSet<'a>, TestingDevice) {
    let mut device = TestingDevice::new(medium);

    let config = Config::new(match medium {
        #[cfg(feature = "medium-ethernet")]
        Medium::Ethernet => {
            HardwareAddress::Ethernet(EthernetAddress([0x02, 0x02, 0x02, 0x02, 0x02, 0x02]))
        }
        #[cfg(feature = "medium-ip")]
        Medium::Ip => HardwareAddress::Ip,
        #[cfg(feature = "medium-ieee802154")]
        Medium::Ieee802154 => HardwareAddress::Ieee802154(Ieee802154Address::Extended([
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        ])),
    });

    let mut iface = Interface::new(config, &mut device, Instant::ZERO);

    #[cfg(feature = "proto-ipv4")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(192, 168, 1, 1), 24))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                .unwrap();
        });
    }

    #[cfg(feature = "proto-ipv6")]
    {
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 128))
                .unwrap();
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0xfdbe, 0, 0, 0, 0, 0, 0, 1), 64))
                .unwrap();
        });
    }

    (iface, SocketSet::new(vec![]), device)
}

/// A testing device.
#[derive(Debug)]
pub struct TestingDevice {
    pub(crate) tx_queue: VecDeque<Vec<u8>>,
    pub(crate) rx_queue: VecDeque<Vec<u8>>,
    max_transmission_unit: usize,
    medium: Medium,
}

#[allow(clippy::new_without_default)]
impl TestingDevice {
    /// Creates a testing device.
    ///
    /// Every packet transmitted through this device will be received through it
    /// in FIFO order.
    pub fn new(medium: Medium) -> Self {
        TestingDevice {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            max_transmission_unit: match medium {
                #[cfg(feature = "medium-ethernet")]
                Medium::Ethernet => 1514,
                #[cfg(feature = "medium-ip")]
                Medium::Ip => 1500,
                #[cfg(feature = "medium-ieee802154")]
                Medium::Ieee802154 => 1500,
            },
            medium,
        }
    }
}

impl Device for TestingDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        DeviceCapabilities {
            medium: self.medium,
            max_transmission_unit: self.max_transmission_unit,
            ..DeviceCapabilities::default()
        }
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx_queue.pop_front().map(move |buffer| {
            let rx = RxToken { buffer };
            let tx = TxToken {
                queue: &mut self.tx_queue,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken {
            queue: &mut self.tx_queue,
        })
    }
}

#[doc(hidden)]
pub struct RxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

#[doc(hidden)]
#[derive(Debug)]
pub struct TxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> phy::TxToken for TxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
