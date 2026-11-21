// Copyright 2016 Pierre-Étienne Meunier
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// https://tools.ietf.org/html/rfc4253#section-12

#[cfg(not(target_arch = "wasm32"))]
pub use server::*;

use crate::{strict_kex_violation, Error};

pub const DISCONNECT: u8 = 1;
#[allow(dead_code)]
pub const IGNORE: u8 = 2;
#[allow(dead_code)]
pub const UNIMPLEMENTED: u8 = 3;
#[allow(dead_code)]
pub const DEBUG: u8 = 4;

pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const EXT_INFO: u8 = 7;
pub const KEXINIT: u8 = 20;
pub const NEWKEYS: u8 = 21;

// http://tools.ietf.org/html/rfc5656#section-7.1
pub const KEX_ECDH_INIT: u8 = 30;
pub const KEX_ECDH_REPLY: u8 = 31;
pub const KEX_DH_GEX_REQUEST: u8 = 34;
pub const KEX_DH_GEX_GROUP: u8 = 31;
pub const KEX_DH_GEX_INIT: u8 = 32;
pub const KEX_DH_GEX_REPLY: u8 = 33;

// PQ/T Hybrid Key Exchange with ML-KEM
// https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/
pub const KEX_HYBRID_INIT: u8 = 30;
#[allow(dead_code)]
pub const KEX_HYBRID_REPLY: u8 = 31;

// https://tools.ietf.org/html/rfc4250#section-4.1.2
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const USERAUTH_BANNER: u8 = 53;

pub const USERAUTH_INFO_RESPONSE: u8 = 61;

// some numbers have same meaning
pub const USERAUTH_INFO_REQUEST_OR_USERAUTH_PK_OK: u8 = 60;
#[allow(dead_code)]
pub const USERAUTH_GSSAPI_RESPONSE: u8 = 60;
pub const USERAUTH_GSSAPI_TOKEN: u8 = 61;
pub const USERAUTH_GSSAPI_EXCHANGE_COMPLETE: u8 = 63;
pub const USERAUTH_GSSAPI_ERROR: u8 = 64;
pub const USERAUTH_GSSAPI_ERRTOK: u8 = 65;
pub const USERAUTH_GSSAPI_MIC: u8 = 66;

// https://tools.ietf.org/html/rfc4254#section-9
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_SUCCESS: u8 = 81;
pub const REQUEST_FAILURE: u8 = 82;

pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;

#[allow(dead_code)]
pub const SSH_OPEN_CONNECT_FAILED: u8 = 2;
pub const SSH_OPEN_UNKNOWN_CHANNEL_TYPE: u8 = 3;
#[allow(dead_code)]
pub const SSH_OPEN_RESOURCE_SHORTAGE: u8 = 4;

#[cfg(not(target_arch = "wasm32"))]
mod server {
    // https://tools.ietf.org/html/rfc4256#section-5
    pub const USERAUTH_INFO_REQUEST: u8 = 60;
    pub const USERAUTH_PK_OK: u8 = 60;
    pub const SSH_OPEN_ADMINISTRATIVELY_PROHIBITED: u8 = 1;
}

/// Validate a message+seqno against a strict kex order pattern
/// Returns:
/// - `Some(true)` if the message is valid at this position
/// - `Some(false)` if the message is invalid at this position
/// - `None` if the `seqno` is not covered by strict kex
fn validate_msg_strict_kex(msg_type: u8, seqno: usize, order: &[u8]) -> Option<bool> {
    order.get(seqno).map(|expected| expected == &msg_type)
}

/// Validate a message+seqno against multiple strict kex order patterns
fn validate_msg_strict_kex_alt_order(msg_type: u8, seqno: usize, orders: &[&[u8]]) -> Option<bool> {
    let mut valid = None; // did not match yet
    for order in orders {
        let result = validate_msg_strict_kex(msg_type, seqno, order);
        valid = match (valid, result) {
            // If we matched a valid msg, it's now valid forever
            (Some(true), _) | (_, Some(true)) => Some(true),
            // If we matched an invalid msg and we didn't find a valid one yet, it's now invalid
            (None | Some(false), Some(false)) => Some(false),
            // If the message was beyond the current pattern, no change
            (x, None) => x,
        };
    }
    valid
}

pub(crate) fn validate_client_msg_strict_kex(msg_type: u8, seqno: usize) -> Result<(), Error> {
    if Some(false)
        == validate_msg_strict_kex_alt_order(
            msg_type,
            seqno,
            &[
                &[KEXINIT, KEX_ECDH_INIT, NEWKEYS],
                &[KEXINIT, KEX_DH_GEX_REQUEST, KEX_DH_GEX_INIT, NEWKEYS],
            ],
        )
    {
        return Err(strict_kex_violation(msg_type, seqno));
    }
    Ok(())
}

pub(crate) fn validate_server_msg_strict_kex(msg_type: u8, seqno: usize) -> Result<(), Error> {
    if Some(false)
        == validate_msg_strict_kex_alt_order(
            msg_type,
            seqno,
            &[
                &[KEXINIT, KEX_ECDH_REPLY, NEWKEYS],
                &[KEXINIT, KEX_DH_GEX_GROUP, KEX_DH_GEX_REPLY, NEWKEYS],
            ],
        )
    {
        return Err(strict_kex_violation(msg_type, seqno));
    }
    Ok(())
}

const ALL_KEX_MESSAGES: &[u8] = &[
    KEXINIT,
    KEX_ECDH_INIT,
    KEX_ECDH_REPLY,
    KEX_DH_GEX_GROUP,
    KEX_DH_GEX_INIT,
    KEX_DH_GEX_REPLY,
    KEX_DH_GEX_REQUEST,
    NEWKEYS,
];

pub(crate) fn is_kex_msg(msg: u8) -> bool {
    ALL_KEX_MESSAGES.contains(&msg)
}
