use std::convert::TryFrom;

use delegate::delegate;
use ssh_encoding::Encode;

#[cfg(feature = "flate2")]
use crate::cipher::MAXIMUM_DECOMPRESSED_PACKET_LEN;

#[derive(Debug, Clone)]
pub enum Compression {
    None,
    #[cfg(feature = "flate2")]
    Zlib,
    #[cfg(feature = "flate2")]
    ZlibOpenSSH,
}

#[derive(Debug)]
pub enum Compress {
    None,
    #[cfg(feature = "flate2")]
    Zlib(flate2::Compress),
}

#[derive(Debug)]
pub enum Decompress {
    None,
    #[cfg(feature = "flate2")]
    Zlib(flate2::Decompress),
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Name(&'static str);
impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl Encode for Name {
    delegate! { to self.as_ref() {
        fn encoded_len(&self) -> Result<usize, ssh_encoding::Error>;
        fn encode(&self, writer: &mut impl ssh_encoding::Writer) -> Result<(), ssh_encoding::Error>;
    }}
}

impl TryFrom<&str> for Name {
    type Error = ();
    fn try_from(s: &str) -> Result<Name, ()> {
        ALL_COMPRESSION_ALGORITHMS
            .iter()
            .find(|x| x.0 == s)
            .map(|x| **x)
            .ok_or(())
    }
}

pub const NONE: Name = Name("none");
#[cfg(feature = "flate2")]
pub const ZLIB: Name = Name("zlib");
#[cfg(feature = "flate2")]
pub const ZLIB_LEGACY: Name = Name("zlib@openssh.com");

pub const ALL_COMPRESSION_ALGORITHMS: &[&Name] = &[
    &NONE,
    #[cfg(feature = "flate2")]
    &ZLIB,
    #[cfg(feature = "flate2")]
    &ZLIB_LEGACY,
];

#[cfg(feature = "flate2")]
impl Compression {
    pub fn new(name: &Name) -> Self {
        if name == &ZLIB {
            Compression::Zlib
        } else if name == &ZLIB_LEGACY {
            Compression::ZlibOpenSSH
        } else {
            Compression::None
        }
    }

    pub fn init_compress(&self, comp: &mut Compress) {
        match *self {
            Compression::Zlib | Compression::ZlibOpenSSH => {
                if let Compress::Zlib(ref mut c) = *comp {
                    c.reset()
                } else {
                    *comp = Compress::Zlib(flate2::Compress::new(flate2::Compression::fast(), true))
                }
            }
            Compression::None => {
                *comp = Compress::None;
            }
        }
    }

    pub fn init_decompress(&self, comp: &mut Decompress) {
        match *self {
            Compression::Zlib | Compression::ZlibOpenSSH => {
                if let Decompress::Zlib(ref mut c) = *comp {
                    c.reset(true)
                } else {
                    *comp = Decompress::Zlib(flate2::Decompress::new(true))
                }
            }
            Compression::None => {
                *comp = Decompress::None;
            }
        }
    }
}

impl Compression {
    /// Returns true if compression should be deferred until after authentication.
    /// "zlib@openssh.com" defers; RFC 4253 "zlib" does not.
    pub fn is_deferred(&self) -> bool {
        match self {
            #[cfg(feature = "flate2")]
            Compression::ZlibOpenSSH => true,
            _ => false,
        }
    }
}

#[cfg(not(feature = "flate2"))]
impl Compression {
    pub fn new(_name: &Name) -> Self {
        Compression::None
    }

    pub fn init_compress(&self, _: &mut Compress) {}

    pub fn init_decompress(&self, _: &mut Decompress) {}
}

#[cfg(not(feature = "flate2"))]
impl Compress {
    pub fn compress<'a>(
        &mut self,
        input: &'a [u8],
        _: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        Ok(input)
    }

    pub fn compress_into(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        start_len: usize,
    ) -> Result<usize, crate::Error> {
        output.truncate(start_len);
        output.extend_from_slice(input);
        Ok(input.len())
    }
}

#[cfg(not(feature = "flate2"))]
impl Decompress {
    pub fn decompress<'a>(
        &mut self,
        input: &'a [u8],
        _: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        Ok(input)
    }
}

#[cfg(all(test, feature = "flate2"))]
mod tests {
    use std::io::Write;

    use flate2::write::ZlibEncoder;

    use super::*;

    #[test]
    fn decompressed_packet_at_limit_is_accepted() {
        let payload = vec![b'A'; MAXIMUM_DECOMPRESSED_PACKET_LEN];
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressor = Decompress::Zlib(flate2::Decompress::new(true));
        let mut output = Vec::new();

        let decompressed = decompressor.decompress(&compressed, &mut output).unwrap();
        assert_eq!(decompressed.len(), MAXIMUM_DECOMPRESSED_PACKET_LEN);
    }

    #[test]
    fn oversized_decompressed_packet_is_rejected() {
        let payload = vec![b'A'; MAXIMUM_DECOMPRESSED_PACKET_LEN + 1024];
        let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        encoder.write_all(&payload).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut decompressor = Decompress::Zlib(flate2::Decompress::new(true));
        let mut output = Vec::new();

        let err = decompressor
            .decompress(&compressed, &mut output)
            .unwrap_err();
        assert!(
            matches!(err, crate::Error::PacketSize(len) if len > MAXIMUM_DECOMPRESSED_PACKET_LEN)
        );
    }

    #[test]
    fn empty_compressed_packet_does_not_spin() {
        let compressed = Vec::new();
        let mut decompressor = Decompress::Zlib(flate2::Decompress::new(true));
        let mut output = Vec::new();

        let decompressed = decompressor.decompress(&compressed, &mut output).unwrap();
        assert!(decompressed.is_empty());
    }

    #[test]
    fn incompressible_packets_round_trip() {
        // Incompressible input makes deflate output land on or past the
        // `input.len() + 10` reservation, so the compress loops must keep
        // going when the buffer comes back exactly full, on both `compress`
        // and `compress_into`.
        let mut comp = Compress::None;
        let mut decomp = Decompress::None;
        Compression::Zlib.init_compress(&mut comp);
        Compression::Zlib.init_decompress(&mut decomp);

        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        for &len in &[1usize, 100, 4096, 32768, 65536, 200_000, 262_144] {
            let payload: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed >> 24) as u8
                })
                .collect();

            let mut cbuf = Vec::new();
            let compressed = comp.compress(&payload, &mut cbuf).unwrap().to_vec();
            let mut dbuf = Vec::new();
            let out = decomp.decompress(&compressed, &mut dbuf).unwrap();
            assert_eq!(out, payload.as_slice(), "compress: {len} bytes");

            let prefix = b"hdr".len();
            let mut cbuf = b"hdr".to_vec();
            let n = comp.compress_into(&payload, &mut cbuf, prefix).unwrap();
            assert_eq!(&cbuf[..prefix], b"hdr");
            assert_eq!(cbuf.len(), prefix + n);
            let mut dbuf = Vec::new();
            let out = decomp.decompress(&cbuf[prefix..], &mut dbuf).unwrap();
            assert_eq!(out, payload.as_slice(), "compress_into: {len} bytes");
        }
    }

    #[test]
    fn partial_flush_packets_round_trip() {
        // Real SSH packets are partial flushes on one continuous stream, not
        // a finished stream, and routinely decompress to more than twice
        // their compressed size.
        let mut comp = Compress::None;
        let mut decomp = Decompress::None;
        Compression::Zlib.init_compress(&mut comp);
        Compression::Zlib.init_decompress(&mut decomp);

        for len in 1..=4096usize {
            let payload: Vec<u8> = (0..len).map(|i| b"abcdefgh"[i % 8]).collect();
            let mut cbuf = Vec::new();
            let compressed = comp.compress(&payload, &mut cbuf).unwrap().to_vec();
            let mut dbuf = Vec::new();
            let out = decomp.decompress(&compressed, &mut dbuf).unwrap();
            assert_eq!(
                out,
                payload.as_slice(),
                "payload of {len} bytes came back wrong"
            );
        }
    }
}

#[cfg(feature = "flate2")]
impl Compress {
    fn zlib_output_reserve_bound(input_len: usize) -> usize {
        input_len.saturating_add(10)
    }

    pub fn compress<'a>(
        &mut self,
        input: &'a [u8],
        output: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        if let Compress::None = *self {
            return Ok(input);
        }
        let n_out_ = self.compress_into(input, output, 0)?;
        #[allow(clippy::indexing_slicing)] // length checked
        Ok(&output[..n_out_])
    }

    pub fn compress_into(
        &mut self,
        input: &[u8],
        output: &mut Vec<u8>,
        start_len: usize,
    ) -> Result<usize, crate::Error> {
        match *self {
            Compress::None => {
                output.truncate(start_len);
                output.extend_from_slice(input);
                Ok(input.len())
            }
            Compress::Zlib(ref mut z) => {
                output.truncate(start_len);
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                let reserve = Self::zlib_output_reserve_bound(input.len());
                output.resize(start_len + reserve, 0);
                let flush = flate2::FlushCompress::Partial;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    #[allow(clippy::indexing_slicing)] // length checked
                    let c =
                        z.compress(&input[n_in_..], &mut output[start_len + n_out_..], flush)?;
                    // See `compress`: full buffer on `Ok` means more pending.
                    let output_full = start_len + (z.total_out() as usize - n_out) == output.len();
                    match c {
                        flate2::Status::BufError => {
                            let growth = output.len().saturating_sub(start_len).max(1);
                            output.resize(output.len() + growth, 0);
                        }
                        _ if output_full => {
                            let growth = output.len().saturating_sub(start_len).max(1);
                            output.resize(output.len() + growth, 0);
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                output.truncate(start_len + n_out_);
                Ok(n_out_)
            }
        }
    }
}

#[cfg(feature = "flate2")]
impl Decompress {
    pub fn decompress<'a>(
        &mut self,
        input: &'a [u8],
        output: &'a mut Vec<u8>,
    ) -> Result<&'a [u8], crate::Error> {
        match *self {
            Decompress::None => Ok(input),
            Decompress::Zlib(ref mut z) => {
                output.clear();
                let n_in = z.total_in() as usize;
                let n_out = z.total_out() as usize;
                let max_output_len = MAXIMUM_DECOMPRESSED_PACKET_LEN
                    .checked_add(1)
                    .ok_or(crate::Error::PacketSize(usize::MAX))?;
                output.resize(input.len().clamp(1, max_output_len), 0);
                let flush = flate2::FlushDecompress::None;
                loop {
                    let n_in_ = z.total_in() as usize - n_in;
                    let n_out_ = z.total_out() as usize - n_out;
                    #[allow(clippy::indexing_slicing)] // length checked
                    let d = z.decompress(&input[n_in_..], &mut output[n_out_..], flush);
                    match d? {
                        flate2::Status::Ok | flate2::Status::BufError => {
                            let made_progress = z.total_in() as usize - n_in != n_in_
                                || z.total_out() as usize - n_out != n_out_;
                            let output_full = z.total_out() as usize - n_out == output.len();

                            // Keep going while calls still produce output: the
                            // inflater can return `BufError` with all input
                            // consumed and decoded bytes still buffered inside
                            // it (miniz_oxide >= 0.9 does exactly that). Only
                            // a call that moves nothing means we're done.
                            if !output_full && !made_progress {
                                break;
                            }

                            if output_full {
                                if output.len() == max_output_len {
                                    break;
                                }
                                let next_len = output
                                    .len()
                                    .checked_mul(2)
                                    .map(|len| len.min(max_output_len))
                                    .ok_or(crate::Error::PacketSize(usize::MAX))?;
                                output.resize(next_len, 0);
                            }
                        }
                        _ => break,
                    }
                }
                let n_out_ = z.total_out() as usize - n_out;
                if n_out_ > MAXIMUM_DECOMPRESSED_PACKET_LEN {
                    return Err(crate::Error::PacketSize(n_out_));
                }
                #[allow(clippy::indexing_slicing)] // length checked
                Ok(&output[..n_out_])
            }
        }
    }
}
