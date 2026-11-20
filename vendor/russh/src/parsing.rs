use ssh_encoding::{Decode, Encode, Reader};

use crate::msg;

use crate::map_err;

/// Require a decoded known-message payload to be fully consumed.
///
/// SSH RFCs and implemented OpenSSH extensions define exact field layouts for
/// known message types. Callers use this after decoding those fields so
/// malformed packets with trailing payload bytes are rejected instead of being
/// treated as canonical messages.
pub(crate) fn ensure_end(reader: &impl Reader) -> Result<(), crate::Error> {
    if reader.is_finished() {
        Ok(())
    } else {
        Err(ssh_encoding::Error::TrailingData {
            remaining: reader.remaining_len(),
        }
        .into())
    }
}

#[derive(Debug)]
pub struct OpenChannelMessage {
    pub typ: ChannelType,
    pub recipient_channel: u32,
    pub recipient_window_size: u32,
    pub recipient_maximum_packet_size: u32,
}

impl OpenChannelMessage {
    /// Parse an SSH `CHANNEL_OPEN` payload.
    ///
    /// Known channel types are parsed according to their fixed layouts and must
    /// not contain trailing bytes. Unknown extension channel types remain
    /// intentionally opaque so applications can implement extension-specific
    /// parsing and compatibility behavior.
    pub fn parse<R: Reader>(r: &mut R) -> Result<Self, crate::Error> {
        // https://tools.ietf.org/html/rfc4254#section-5.1
        let typ = map_err!(String::decode(r))?;
        let sender = map_err!(u32::decode(r))?;
        let window = map_err!(u32::decode(r))?;
        let maxpacket = map_err!(u32::decode(r))?;
        // A zero max packet size can never be satisfied, so writes would stall forever.
        if maxpacket == 0 {
            return Err(crate::Error::Inconsistent);
        }

        let typ = match typ.as_str() {
            "session" => {
                ensure_end(r)?;
                ChannelType::Session
            }
            "x11" => {
                let originator_address = map_err!(String::decode(r))?;
                let originator_port = map_err!(u32::decode(r))?;
                ensure_end(r)?;
                ChannelType::X11 {
                    originator_address,
                    originator_port,
                }
            }
            "direct-tcpip" => {
                let info = TcpChannelInfo::decode(r)?;
                ensure_end(r)?;
                ChannelType::DirectTcpip(info)
            }
            "direct-streamlocal@openssh.com" => {
                let info = StreamLocalChannelInfo::decode(r)?;
                String::decode(r)?; // originator address/reserved
                u32::decode(r)?; // originator port/reserved
                ensure_end(r)?;
                ChannelType::DirectStreamLocal(info)
            }
            "forwarded-tcpip" => {
                let info = TcpChannelInfo::decode(r)?;
                ensure_end(r)?;
                ChannelType::ForwardedTcpIp(info)
            }
            "forwarded-streamlocal@openssh.com" => {
                let info = StreamLocalChannelInfo::decode(r)?;
                String::decode(r)?; // reserved
                ensure_end(r)?;
                ChannelType::ForwardedStreamLocal(info)
            }
            "auth-agent@openssh.com" => {
                ensure_end(r)?;
                ChannelType::AgentForward
            }
            _ => ChannelType::Unknown { typ },
        };

        Ok(Self {
            typ,
            recipient_channel: sender,
            recipient_window_size: window,
            recipient_maximum_packet_size: maxpacket,
        })
    }


    /// Pushes a failure message to the vec.
    pub fn fail(
        &self,
        buffer: &mut Vec<u8>,
        reason: u8,
        message: &[u8],
    ) -> Result<(), crate::Error> {
        push_packet!(buffer, {
            msg::CHANNEL_OPEN_FAILURE.encode(buffer)?;
            self.recipient_channel.encode(buffer)?;
            (reason as u32).encode(buffer)?;
            message.encode(buffer)?;
            "en".encode(buffer)?;
        });
        Ok(())
    }

    /// Pushes an unknown type error to the vec.
    pub fn unknown_type(&self, buffer: &mut Vec<u8>) -> Result<(), crate::Error> {
        self.fail(
            buffer,
            msg::SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
            b"Unknown channel type",
        )
    }
}

#[derive(Debug)]
pub enum ChannelType {
    Session,
    X11 {
        originator_address: String,
        originator_port: u32,
    },
    DirectTcpip(TcpChannelInfo),
    DirectStreamLocal(StreamLocalChannelInfo),
    ForwardedTcpIp(TcpChannelInfo),
    ForwardedStreamLocal(StreamLocalChannelInfo),
    AgentForward,
    Unknown {
        typ: String,
    },
}

#[derive(Debug)]
pub struct TcpChannelInfo {
    pub host_to_connect: String,
    pub port_to_connect: u32,
    pub originator_address: String,
    pub originator_port: u32,
}

#[derive(Debug)]
pub struct StreamLocalChannelInfo {
    pub socket_path: String,
}

impl Decode for StreamLocalChannelInfo {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let socket_path = String::decode(r)?.to_owned();
        Ok(Self { socket_path })
    }
}

impl Decode for TcpChannelInfo {
    type Error = ssh_encoding::Error;

    fn decode(r: &mut impl Reader) -> Result<Self, Self::Error> {
        let host_to_connect = String::decode(r)?;
        let port_to_connect = u32::decode(r)?;
        let originator_address = String::decode(r)?;
        let originator_port = u32::decode(r)?;

        Ok(Self {
            host_to_connect,
            port_to_connect,
            originator_address,
            originator_port,
        })
    }
}

#[derive(Debug)]
pub(crate) struct ChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window_size: u32,
    pub maximum_packet_size: u32,
}

impl ChannelOpenConfirmation {
    pub fn parse(r: &mut impl Reader) -> Result<Self, crate::Error> {
        let recipient_channel = u32::decode(r)?;
        let sender_channel = u32::decode(r)?;
        let initial_window_size = u32::decode(r)?;
        let maximum_packet_size = u32::decode(r)?;
        // See OpenChannelMessage::parse.
        if maximum_packet_size == 0 {
            return Err(crate::Error::Inconsistent);
        }

        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{ChannelOpenConfirmation, ChannelType, OpenChannelMessage};
    use crate::tests::raw_no_crypto::{channel_open_payload, encode_string, push_u32};

    #[test]
    fn known_channel_open_with_trailing_bytes_is_rejected() {
        let mut payload = channel_open_payload(b"session");
        payload.push(0);

        assert!(
            OpenChannelMessage::parse(&mut payload.as_slice()).is_err(),
            "known channel-open type accepted trailing bytes"
        );
    }

    #[test]
    fn unknown_channel_open_with_extra_payload_stays_permissive() {
        let mut payload = channel_open_payload(b"unknown@example.com");
        payload.extend_from_slice(b"opaque");

        let parsed = OpenChannelMessage::parse(&mut payload.as_slice())
            .expect("unknown channel-open payload should remain opaque");

        assert!(matches!(parsed.typ, ChannelType::Unknown { .. }));
    }

    #[test]
    fn openssh_streamlocal_channel_open_reserved_fields_are_consumed() {
        let mut direct = channel_open_payload(b"direct-streamlocal@openssh.com");
        encode_string(&mut direct, b"/tmp/socket");
        encode_string(&mut direct, b"");
        push_u32(&mut direct, 0);

        let parsed = OpenChannelMessage::parse(&mut direct.as_slice())
            .expect("direct streamlocal reserved fields should be consumed");
        assert!(matches!(parsed.typ, ChannelType::DirectStreamLocal(_)));

        let mut forwarded = channel_open_payload(b"forwarded-streamlocal@openssh.com");
        encode_string(&mut forwarded, b"/tmp/socket");
        encode_string(&mut forwarded, b"");

        let parsed = OpenChannelMessage::parse(&mut forwarded.as_slice())
            .expect("forwarded streamlocal reserved field should be consumed");
        assert!(matches!(parsed.typ, ChannelType::ForwardedStreamLocal(_)));
    }

    #[test]
    fn channel_open_with_zero_max_packet_size_is_rejected() {
        let mut payload = Vec::new();
        encode_string(&mut payload, b"session");
        push_u32(&mut payload, 0); // sender channel
        push_u32(&mut payload, 1024 * 1024); // window
        push_u32(&mut payload, 0); // max packet size

        assert!(matches!(
            OpenChannelMessage::parse(&mut payload.as_slice()),
            Err(crate::Error::Inconsistent)
        ));
    }

    #[test]
    fn channel_open_confirmation_with_zero_max_packet_size_is_rejected() {
        let confirmation = |max_packet: u32| {
            let mut payload = Vec::new();
            push_u32(&mut payload, 0); // recipient channel
            push_u32(&mut payload, 1); // sender channel
            push_u32(&mut payload, 1024 * 1024); // window
            push_u32(&mut payload, max_packet);
            payload
        };

        assert!(matches!(
            ChannelOpenConfirmation::parse(&mut confirmation(0).as_slice()),
            Err(crate::Error::Inconsistent)
        ));
        let ok = ChannelOpenConfirmation::parse(&mut confirmation(32 * 1024).as_slice())
            .expect("non-zero max packet size should be accepted");
        assert_eq!(ok.maximum_packet_size, 32 * 1024);
    }
}
