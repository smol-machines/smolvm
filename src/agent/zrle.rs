//! ZRLE encoding for the RFB server (encoding 16, RFC 6143 §7.7.6).
//!
//! Raw encoding ships every pixel uncompressed. On a 1280x800 desktop that is
//! 4 MB per full update and tens of MB/s with nothing moving but a cursor —
//! the difference between a session that feels immediate and one that is
//! unusable, especially once the viewer also has to decode and rescale it.
//!
//! ZRLE is the right answer rather than Tight: it is part of RFC 6143 proper,
//! every mainstream viewer implements it, and it needs one zlib stream and no
//! JPEG codec. Tight compresses a little better on photographic content at the
//! cost of several zlib streams, filters and a JPEG dependency — more surface
//! to get subtly wrong for a gain that does not matter on desktop pixels.
//!
//! Scope here is the two subencodings that carry desktop content: solid tiles
//! and raw tiles. Both are fully conformant — a server may choose any
//! subencoding per tile — and they are what makes a desktop cheap: flat areas
//! collapse to a single pixel each, and zlib squeezes the rest.

use flate2::{Compress, Compression, FlushCompress};

/// ZRLE always works in 64x64 tiles, left to right then top to bottom. Edge
/// tiles are clipped, never padded.
const TILE: usize = 64;

/// How a pixel is written inside a ZRLE tile.
///
/// ZRLE uses "CPIXEL", which drops a byte that carries no colour: with 32 bits
/// per pixel, a depth of 24 or less, and every significant bit inside the top
/// or bottom three bytes, a pixel travels as 3 bytes instead of 4. That alone
/// is a 25% saving before zlib sees anything.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Cpixel {
    /// Bytes actually written per pixel: 3 when a byte can be dropped, else 4.
    pub(crate) size: usize,
    /// Index into the 4 serialized bytes where the compressed pixel starts.
    offset: usize,
}

impl Cpixel {
    /// Work out the CPIXEL layout for a client's pixel format.
    pub(crate) fn for_format(fmt: &super::vnc::PixelFormat) -> Self {
        let (bpp, depth, big_endian, mask) = fmt.cpixel_inputs();
        if bpp != 32 || depth > 24 {
            return Self { size: 4, offset: 0 };
        }
        // "All bits in the least significant or most significant 3 bytes."
        if mask & 0xFF00_0000 == 0 {
            // Significant bytes are the low three.
            Self {
                size: 3,
                offset: if big_endian { 1 } else { 0 },
            }
        } else if mask & 0x0000_00FF == 0 {
            // Significant bytes are the high three.
            Self {
                size: 3,
                offset: if big_endian { 0 } else { 1 },
            }
        } else {
            Self { size: 4, offset: 0 }
        }
    }

    /// Append one pixel, given its four serialized bytes.
    #[inline]
    fn push(&self, out: &mut Vec<u8>, px: &[u8; 4]) {
        out.extend_from_slice(&px[self.offset..self.offset + self.size]);
    }
}

/// A rectangle of the framebuffer, in pixels.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Rect {
    pub(crate) x: usize,
    pub(crate) y: usize,
    pub(crate) w: usize,
    pub(crate) h: usize,
}

/// Per-connection ZRLE encoder.
pub(crate) struct Encoder {
    compress: Compress,
    /// Uncompressed tile stream, reused across rectangles.
    tiles: Vec<u8>,
    /// Compressed output, reused across rectangles.
    out: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self {
            // Level 1: this is a live display, not an archive. The pixels are
            // already cheap after solid-tile collapsing, and a slower level
            // would cost more latency than it saves bandwidth.
            compress: Compress::new(Compression::fast(), true),
            tiles: Vec::new(),
            out: Vec::new(),
        }
    }

    /// Encode one rectangle, returning the ZRLE rectangle payload: a big-endian
    /// u32 byte count followed by that many zlib bytes.
    ///
    /// 🔴 The zlib stream is continuous for the life of the connection. The
    /// client inflates every rectangle through one stream, so this must never
    /// be reset between rectangles or updates — the client would desynchronise
    /// and render garbage from that point on.
    pub(crate) fn encode_rect(
        &mut self,
        pixels: &[u8],
        fb_width: usize,
        rect: Rect,
        cpixel: Cpixel,
    ) -> Vec<u8> {
        self.tiles.clear();
        for ty in (0..rect.h).step_by(TILE) {
            let th = TILE.min(rect.h - ty);
            for tx in (0..rect.w).step_by(TILE) {
                let tw = TILE.min(rect.w - tx);
                let tile = Rect {
                    x: rect.x + tx,
                    y: rect.y + ty,
                    w: tw,
                    h: th,
                };
                self.push_tile(pixels, fb_width, tile, cpixel);
            }
        }

        self.out.clear();
        let mut consumed = 0usize;
        loop {
            // Always offer real space, and notice whether zlib used all of it.
            self.out.reserve(4096);
            let spare = self.out.capacity() - self.out.len();
            let before_in = self.compress.total_in();
            let before_out = self.compress.total_out();
            // Sync flush: the client must be able to decode this rectangle now,
            // without waiting for whatever we send next.
            let _ = self.compress.compress_vec(
                &self.tiles[consumed..],
                &mut self.out,
                FlushCompress::Sync,
            );
            consumed += (self.compress.total_in() - before_in) as usize;
            let produced = (self.compress.total_out() - before_out) as usize;
            // 🔴 Termination cannot be "produced nothing": a sync flush emits an
            // empty stored block on every call, even with no input left, so that
            // condition never comes true and the loop spins forever. zlib is
            // done when it has taken all the input and did not need all the
            // room we gave it.
            if consumed == self.tiles.len() && produced < spare {
                break;
            }
        }

        let mut rect = Vec::with_capacity(self.out.len() + 4);
        rect.extend_from_slice(&(self.out.len() as u32).to_be_bytes());
        rect.extend_from_slice(&self.out);
        rect
    }

    fn push_tile(&mut self, pixels: &[u8], fb_width: usize, tile: Rect, cpixel: Cpixel) {
        let Rect { x, y, w, h } = tile;
        let at = |px: usize, py: usize| -> [u8; 4] {
            let i = (py * fb_width + px) * 4;
            [pixels[i], pixels[i + 1], pixels[i + 2], pixels[i + 3]]
        };

        let first = at(x, y);
        let solid = (0..h).all(|row| (0..w).all(|col| at(x + col, y + row) == first));
        if solid {
            self.tiles.push(1); // subencoding 1: one colour for the whole tile
            cpixel.push(&mut self.tiles, &first);
            return;
        }

        self.tiles.push(0); // subencoding 0: raw CPIXELs, row major
        for row in 0..h {
            for col in 0..w {
                cpixel.push(&mut self.tiles, &at(x + col, y + row));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Decompress, FlushDecompress};

    /// A minimal ZRLE client, so the tests check what a viewer would actually
    /// reconstruct rather than what the encoder believes it wrote. Encoding
    /// bugs here are invisible in any other kind of test: the session simply
    /// renders garbage on someone else's screen.
    struct Viewer {
        inflate: Decompress,
    }

    impl Viewer {
        fn new() -> Self {
            Self {
                // One stream for the connection, exactly like the encoder.
                inflate: Decompress::new(true),
            }
        }

        /// Returns the rectangle's pixels as CPIXEL bytes, row major.
        fn decode_rect(&mut self, payload: &[u8], w: usize, h: usize, cp: Cpixel) -> Vec<u8> {
            let len = u32::from_be_bytes(payload[..4].try_into().unwrap()) as usize;
            assert_eq!(payload.len(), 4 + len, "payload length prefix disagrees");

            let mut raw = Vec::new();
            let mut consumed = 0usize;
            loop {
                raw.reserve(4096);
                let spare = raw.capacity() - raw.len();
                let before_in = self.inflate.total_in();
                let before_out = self.inflate.total_out();
                self.inflate
                    .decompress_vec(&payload[4 + consumed..], &mut raw, FlushDecompress::Sync)
                    .expect("inflate failed: the zlib stream is corrupt");
                consumed += (self.inflate.total_in() - before_in) as usize;
                let produced = (self.inflate.total_out() - before_out) as usize;
                if consumed == len && produced < spare {
                    break;
                }
            }

            let mut out = vec![0u8; w * h * cp.size];
            let mut at = 0usize;
            for ty in (0..h).step_by(TILE) {
                let th = TILE.min(h - ty);
                for tx in (0..w).step_by(TILE) {
                    let tw = TILE.min(w - tx);
                    let sub = raw[at];
                    at += 1;
                    match sub {
                        1 => {
                            let px = &raw[at..at + cp.size];
                            at += cp.size;
                            for row in 0..th {
                                for col in 0..tw {
                                    let o = ((ty + row) * w + tx + col) * cp.size;
                                    out[o..o + cp.size].copy_from_slice(px);
                                }
                            }
                        }
                        0 => {
                            for row in 0..th {
                                for col in 0..tw {
                                    let o = ((ty + row) * w + tx + col) * cp.size;
                                    out[o..o + cp.size].copy_from_slice(&raw[at..at + cp.size]);
                                    at += cp.size;
                                }
                            }
                        }
                        other => panic!("unexpected ZRLE subencoding {other}"),
                    }
                }
            }
            assert_eq!(at, raw.len(), "tile stream had trailing bytes");
            out
        }
    }

    /// What a viewer should end up with for BGRX source pixels, where CPIXEL
    /// keeps the low three bytes.
    fn expected_bgr(
        src: &[u8],
        fb_width: usize,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(w * h * 3);
        for row in 0..h {
            for col in 0..w {
                let i = ((y + row) * fb_width + x + col) * 4;
                out.extend_from_slice(&src[i..i + 3]);
            }
        }
        out
    }

    fn bgrx_cpixel() -> Cpixel {
        Cpixel::for_format(&crate::agent::vnc::PixelFormat::bgrx())
    }

    fn image(w: usize, h: usize, f: impl Fn(usize, usize) -> [u8; 4]) -> Vec<u8> {
        let mut v = Vec::with_capacity(w * h * 4);
        for y in 0..h {
            for x in 0..w {
                v.extend_from_slice(&f(x, y));
            }
        }
        v
    }

    #[test]
    fn a_solid_image_round_trips() {
        let (w, h) = (128, 128);
        let src = image(w, h, |_, _| [10, 20, 30, 255]);
        let cp = bgrx_cpixel();
        let mut enc = Encoder::new();
        let payload = enc.encode_rect(&src, w, Rect { x: 0, y: 0, w, h }, cp);
        let got = Viewer::new().decode_rect(&payload, w, h, cp);
        assert_eq!(got, expected_bgr(&src, w, 0, 0, w, h));
    }

    #[test]
    fn a_detailed_image_round_trips() {
        let (w, h) = (200, 150);
        // Deterministic pseudo-noise: every tile differs, so nothing is solid.
        let src = image(w, h, |x, y| {
            let v = ((x * 7919 + y * 104_729) % 251) as u8;
            [v, v.wrapping_mul(3), v.wrapping_add(97), 255]
        });
        let cp = bgrx_cpixel();
        let mut enc = Encoder::new();
        let payload = enc.encode_rect(&src, w, Rect { x: 0, y: 0, w, h }, cp);
        let got = Viewer::new().decode_rect(&payload, w, h, cp);
        assert_eq!(got, expected_bgr(&src, w, 0, 0, w, h));
    }

    /// Edge tiles are clipped, never padded: a size that is not a multiple of
    /// 64 in either axis is the case that silently shears an image.
    #[test]
    fn sizes_that_are_not_a_multiple_of_the_tile_round_trip() {
        for (w, h) in [(65, 1), (1, 65), (63, 63), (130, 70), (1280, 800)] {
            let src = image(w, h, |x, y| [(x % 256) as u8, (y % 256) as u8, 7, 255]);
            let cp = bgrx_cpixel();
            let mut enc = Encoder::new();
            let payload = enc.encode_rect(&src, w, Rect { x: 0, y: 0, w, h }, cp);
            let got = Viewer::new().decode_rect(&payload, w, h, cp);
            assert_eq!(got, expected_bgr(&src, w, 0, 0, w, h), "{w}x{h}");
        }
    }

    /// 🔴 The zlib stream is continuous for the life of a connection. If the
    /// encoder ever reset it, the first rectangle would decode and everything
    /// after it would be garbage — which is why this sends several through one
    /// encoder and decodes them through one viewer.
    #[test]
    fn successive_rectangles_share_one_zlib_stream() {
        let (w, h) = (192, 96);
        let cp = bgrx_cpixel();
        let mut enc = Encoder::new();
        let mut viewer = Viewer::new();
        for round in 0..6u8 {
            let src = image(w, h, |x, y| {
                let v = (x + y + round as usize * 13) as u8;
                [v, v.wrapping_mul(5), round, 255]
            });
            let payload = enc.encode_rect(&src, w, Rect { x: 0, y: 0, w, h }, cp);
            let got = viewer.decode_rect(&payload, w, h, cp);
            assert_eq!(got, expected_bgr(&src, w, 0, 0, w, h), "round {round}");
        }
    }

    /// Band updates encode a sub-rectangle of a larger framebuffer, so the
    /// encoder has to honour the stride rather than assume the rect is the
    /// whole image.
    #[test]
    fn a_band_of_a_larger_framebuffer_round_trips() {
        let (fw, fh) = (320, 240);
        let src = image(fw, fh, |x, y| [(x % 256) as u8, (y % 256) as u8, 42, 255]);
        let (x, y, w, h) = (0, 96, fw, 32);
        let cp = bgrx_cpixel();
        let mut enc = Encoder::new();
        let payload = enc.encode_rect(&src, fw, Rect { x, y, w, h }, cp);
        let got = Viewer::new().decode_rect(&payload, w, h, cp);
        assert_eq!(got, expected_bgr(&src, fw, x, y, w, h));
    }

    #[test]
    fn solid_content_is_dramatically_smaller_than_raw() {
        let (w, h) = (1280, 800);
        let src = image(w, h, |_, _| [30, 40, 50, 255]);
        let cp = bgrx_cpixel();
        let mut enc = Encoder::new();
        let payload = enc.encode_rect(&src, w, Rect { x: 0, y: 0, w, h }, cp);
        let raw = w * h * 4;
        assert!(
            payload.len() * 100 < raw,
            "a flat 1280x800 screen took {} bytes against {raw} raw",
            payload.len()
        );
    }

    #[test]
    fn cpixel_drops_the_unused_byte_only_when_it_can() {
        let bgrx = bgrx_cpixel();
        assert_eq!(bgrx.size, 3, "32bpp depth-24 BGRX must travel as 3 bytes");
        assert_eq!(bgrx.offset, 0, "little-endian keeps the low three bytes");
    }
}
