//! Negotiated binary payloads inside the existing four-byte length framing.
//!
//! JSON control envelopes advertise `binary_stream: 1`. A host only sends
//! binary requests after an agent echoes that version; agents only send binary
//! responses after a host advertises it. Old peers continue using JSON.
//! Binary bodies are `0 | version:u8 | kind:u8 | payload`. Request payloads
//! start with a big-endian u32 trace-id length and UTF-8 trace ID. DataChunk
//! payloads start with a strictly boolean completion byte. All other bytes
//! are raw data; the existing outer frame limit remains in force.

use crate::{AgentRequest, AgentResponse, Envelope, MAX_FRAME_SIZE};
use std::io::{self, Write};

/// Supported binary streaming version.
pub const VERSION: u8 = 1;
const STDIN: u8 = 1;
const FILE_WRITE_CHUNK: u8 = 2;
const STDOUT: u8 = 3;
const STDERR: u8 = 4;
const DATA_CHUNK: u8 = 5;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn kind(body: &[u8]) -> io::Result<Option<u8>> {
    if body.len() > MAX_FRAME_SIZE as usize {
        return Err(invalid("binary frame exceeds maximum size"));
    }
    if body.first() != Some(&0) {
        return Ok(None);
    }
    if body.len() < 3 || body[1] != VERSION {
        return Err(invalid("invalid binary streaming version or header"));
    }
    Ok(Some(body[2]))
}

/// Encode a bulk request when supported, otherwise return `None` for JSON.
pub fn encode_request(
    request: &AgentRequest,
    trace_id: Option<&str>,
) -> io::Result<Option<Vec<u8>>> {
    let (tag, data, done) = match request {
        AgentRequest::Stdin { data } => (STDIN, data, None),
        AgentRequest::FileWriteChunk { data, done } => (FILE_WRITE_CHUNK, data, Some(*done)),
        _ => return Ok(None),
    };
    let trace = trace_id.unwrap_or("").as_bytes();
    let len = (7 + usize::from(done.is_some()))
        .checked_add(trace.len())
        .and_then(|n| n.checked_add(data.len()))
        .filter(|n| *n <= MAX_FRAME_SIZE as usize)
        .ok_or_else(|| invalid("binary request exceeds maximum size"))?;
    let mut frame = Vec::with_capacity(4 + len);
    frame.extend_from_slice(&(len as u32).to_be_bytes());
    frame.extend_from_slice(&[0, VERSION, tag]);
    frame.extend_from_slice(&(trace.len() as u32).to_be_bytes());
    frame.extend_from_slice(trace);
    if let Some(done) = done {
        frame.push(u8::from(done));
    }
    frame.extend_from_slice(data);
    Ok(Some(frame))
}

/// Decode a request body, accepting both negotiated binary and legacy JSON.
pub fn decode_request(body: &[u8]) -> io::Result<Envelope<AgentRequest>> {
    let Some(tag) = kind(body)? else {
        return serde_json::from_slice(body).map_err(|e| invalid(&e.to_string()));
    };
    if !matches!(tag, STDIN | FILE_WRITE_CHUNK) || body.len() < 7 {
        return Err(invalid("invalid binary request kind or trace header"));
    }
    let len = u32::from_be_bytes(body[3..7].try_into().unwrap()) as usize;
    let trace = body
        .get(7..7usize.saturating_add(len))
        .ok_or_else(|| invalid("truncated binary trace ID"))?;
    let trace = std::str::from_utf8(trace).map_err(|_| invalid("invalid binary trace ID"))?;
    let payload = &body[7 + len..];
    let request = if tag == STDIN {
        AgentRequest::Stdin {
            data: payload.to_vec(),
        }
    } else {
        let (&done, data) = payload
            .split_first()
            .filter(|(done, _)| **done <= 1)
            .ok_or_else(|| invalid("invalid binary upload completion flag"))?;
        AgentRequest::FileWriteChunk {
            data: data.to_vec(),
            done: done == 1,
        }
    };
    let mut envelope =
        Envelope::with_trace_id(request, (!trace.is_empty()).then(|| trace.to_owned()));
    envelope.binary_stream = Some(VERSION);
    Ok(envelope)
}

/// Write a bulk response directly from its payload without JSON/base64 or a
/// second payload-sized framing buffer. Return false for a control response.
pub fn write_response(writer: &mut impl Write, response: &AgentResponse) -> io::Result<bool> {
    let (tag, data, done) = match response {
        AgentResponse::Stdout { data } => (STDOUT, data, None),
        AgentResponse::Stderr { data } => (STDERR, data, None),
        AgentResponse::DataChunk { data, done } => (DATA_CHUNK, data, Some(*done)),
        _ => return Ok(false),
    };
    let len = 3 + usize::from(done.is_some()) + data.len();
    if len > MAX_FRAME_SIZE as usize {
        return Err(invalid("binary response exceeds maximum size"));
    }
    let mut header = [0; 8];
    header[..4].copy_from_slice(&(len as u32).to_be_bytes());
    header[4..7].copy_from_slice(&[0, VERSION, tag]);
    let header_len = if let Some(done) = done {
        header[7] = u8::from(done);
        8
    } else {
        7
    };
    writer.write_all(&header[..header_len])?;
    writer.write_all(data)?;
    Ok(true)
}

/// Decode a response body and whether it acknowledges binary streaming.
pub fn decode_response(body: &[u8]) -> io::Result<(AgentResponse, bool)> {
    let Some(tag) = kind(body)? else {
        // Decode the response itself directly: flattened enum defaults must
        // retain exactly the same behavior as the legacy JSON decoder.
        #[derive(serde::Deserialize)]
        struct Version {
            binary_stream: Option<u8>,
        }
        let version: Version = serde_json::from_slice(body).map_err(|e| invalid(&e.to_string()))?;
        let response = serde_json::from_slice(body).map_err(|e| invalid(&e.to_string()))?;
        return Ok((response, version.binary_stream == Some(VERSION)));
    };
    let response = match tag {
        STDOUT => AgentResponse::Stdout {
            data: body[3..].to_vec(),
        },
        STDERR => AgentResponse::Stderr {
            data: body[3..].to_vec(),
        },
        DATA_CHUNK if body.get(3).is_some_and(|b| *b <= 1) => AgentResponse::DataChunk {
            data: body[4..].to_vec(),
            done: body[3] == 1,
        },
        _ => return Err(invalid("invalid binary response kind or completion flag")),
    };
    Ok((response, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_requests_roundtrip_bytes_trace_and_eof() {
        for data in [vec![], (0..=255).cycle().take(65537).collect()] {
            for request in [
                AgentRequest::Stdin { data: data.clone() },
                AgentRequest::FileWriteChunk {
                    data: data.clone(),
                    done: false,
                },
                AgentRequest::FileWriteChunk { data, done: true },
            ] {
                let frame = encode_request(&request, Some("trace-λ")).unwrap().unwrap();
                assert_eq!(
                    u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
                    frame.len() - 4
                );
                let decoded = decode_request(&frame[4..]).unwrap();
                assert_eq!(decoded.trace_id.as_deref(), Some("trace-λ"));
                assert_eq!(
                    serde_json::to_value(decoded.body).unwrap(),
                    serde_json::to_value(request).unwrap()
                );
            }
        }
    }

    #[test]
    fn bulk_responses_roundtrip_without_base64_expansion() {
        for data in [vec![], (0..=255).cycle().take(65537).collect()] {
            for response in [
                AgentResponse::Stdout { data: data.clone() },
                AgentResponse::Stderr { data: data.clone() },
                AgentResponse::DataChunk {
                    data: data.clone(),
                    done: false,
                },
                AgentResponse::DataChunk {
                    data: data.clone(),
                    done: true,
                },
            ] {
                let mut frame = Vec::new();
                assert!(write_response(&mut frame, &response).unwrap());
                assert!(frame.len() <= data.len() + 8);
                let (decoded, binary) = decode_response(&frame[4..]).unwrap();
                assert!(binary);
                assert_eq!(
                    serde_json::to_value(decoded).unwrap(),
                    serde_json::to_value(response).unwrap()
                );
            }
        }
    }

    #[test]
    fn legacy_json_and_control_acknowledgments_remain_compatible() {
        let request = AgentRequest::Stdin { data: vec![0, 255] };
        let body = serde_json::to_vec(&request).unwrap();
        assert!(decode_request(&body).unwrap().binary_stream.is_none());
        let response = AgentResponse::Started;
        let body = serde_json::to_vec(&response).unwrap();
        assert!(!decode_response(&body).unwrap().1);
        let mut envelope = Envelope::new(response);
        envelope.binary_stream = Some(VERSION);
        let body = serde_json::to_vec(&envelope).unwrap();
        assert!(matches!(
            serde_json::from_slice::<AgentResponse>(&body).unwrap(),
            AgentResponse::Started
        ));
        assert!(decode_response(&body).unwrap().1);
        assert!(encode_request(&AgentRequest::Ping, None).unwrap().is_none());
    }

    #[test]
    fn malformed_and_wrong_direction_binary_frames_are_rejected() {
        for body in [vec![0], vec![0, 1], vec![0, 2, STDIN], vec![0, 1, 255]] {
            assert!(decode_request(&body).is_err());
            assert!(decode_response(&body).is_err());
        }
        for body in [
            vec![0, 1, STDIN],
            vec![0, 1, FILE_WRITE_CHUNK],
            vec![0, 1, STDIN, 255, 255, 255, 255],
        ] {
            assert!(decode_request(&body).is_err());
        }
        assert!(decode_request(&[0, 1, STDIN, 0, 0, 0, 1, 255]).is_err());
        assert!(decode_request(&[0, 1, FILE_WRITE_CHUNK, 0, 0, 0, 0, 2]).is_err());
        assert!(decode_response(&[0, 1, DATA_CHUNK]).is_err());
        assert!(decode_response(&[0, 1, DATA_CHUNK, 2]).is_err());
        assert!(decode_response(&[0, 1, STDIN]).is_err());
        assert!(decode_request(&[0, 1, STDOUT]).is_err());
    }
}
