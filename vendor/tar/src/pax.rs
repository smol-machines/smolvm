#![allow(dead_code)]
use std::io;
use std::io::Write;
use std::str;

use crate::other;

// Keywords for PAX extended header records.
pub const PAX_NONE: &str = ""; // Indicates that no PAX key is suitable
pub const PAX_PATH: &str = "path";
pub const PAX_LINKPATH: &str = "linkpath";
pub const PAX_SIZE: &str = "size";
pub const PAX_UID: &str = "uid";
pub const PAX_GID: &str = "gid";
pub const PAX_UNAME: &str = "uname";
pub const PAX_GNAME: &str = "gname";
pub const PAX_MTIME: &str = "mtime";
pub const PAX_ATIME: &str = "atime";
pub const PAX_CTIME: &str = "ctime"; // Removed from later revision of PAX spec, but was valid
pub const PAX_CHARSET: &str = "charset"; // Currently unused
pub const PAX_COMMENT: &str = "comment"; // Currently unused

pub const PAX_SCHILYXATTR: &str = "SCHILY.xattr.";

// Keywords for GNU sparse files in a PAX extended header.
pub const PAX_GNUSPARSE: &str = "GNU.sparse.";
pub const PAX_GNUSPARSENUMBLOCKS: &str = "GNU.sparse.numblocks";
pub const PAX_GNUSPARSEOFFSET: &str = "GNU.sparse.offset";
pub const PAX_GNUSPARSENUMBYTES: &str = "GNU.sparse.numbytes";
pub const PAX_GNUSPARSEMAP: &str = "GNU.sparse.map";
pub const PAX_GNUSPARSENAME: &str = "GNU.sparse.name";
pub const PAX_GNUSPARSEMAJOR: &str = "GNU.sparse.major";
pub const PAX_GNUSPARSEMINOR: &str = "GNU.sparse.minor";
pub const PAX_GNUSPARSESIZE: &str = "GNU.sparse.size";
pub const PAX_GNUSPARSEREALSIZE: &str = "GNU.sparse.realsize";

/// An iterator over the pax extensions in an archive entry.
///
/// This iterator yields structures which can themselves be parsed into
/// key/value pairs.
pub struct PaxExtensions<'entry> {
    data: &'entry [u8],
}

impl<'entry> PaxExtensions<'entry> {
    /// Create new pax extensions iterator from the given entry data.
    pub fn new(a: &'entry [u8]) -> Self {
        PaxExtensions { data: a }
    }
}

/// A key/value pair corresponding to a pax extension.
pub struct PaxExtension<'entry> {
    key: &'entry [u8],
    value: &'entry [u8],
}

pub fn pax_extensions_value(a: &[u8], key: &str) -> Option<u64> {
    for extension in PaxExtensions::new(a) {
        let current_extension = match extension {
            Ok(ext) => ext,
            Err(_) => return None,
        };
        if current_extension.key() != Ok(key) {
            continue;
        }

        let value = match current_extension.value() {
            Ok(value) => value,
            Err(_) => return None,
        };
        let result = match value.parse::<u64>() {
            Ok(result) => result,
            Err(_) => return None,
        };
        return Some(result);
    }
    None
}

impl<'entry> Iterator for PaxExtensions<'entry> {
    type Item = io::Result<PaxExtension<'entry>>;

    fn next(&mut self) -> Option<io::Result<PaxExtension<'entry>>> {
        if self.data.is_empty() {
            return None;
        }
        // A value may itself contain newlines. The decimal prefix covers the
        // entire record (including the prefix and final newline), in bytes.
        // Stop on invalid framing rather than guessing where another begins.
        let data = std::mem::take(&mut self.data);
        let record = (|| {
            let space = data.iter().position(|b| *b == b' ')?;
            if space == 0 || !data[..space].iter().all(u8::is_ascii_digit) {
                return None;
            }
            let length = str::from_utf8(&data[..space]).ok()?.parse::<usize>().ok()?;
            let record = data.get(..length)?;
            if record.last() != Some(&b'\n') || length <= space + 3 {
                return None;
            }
            let pair = &record[space + 1..length - 1];
            let equals = pair.iter().position(|b| *b == b'=')?;
            if equals == 0 {
                return None;
            }
            Some((
                length,
                PaxExtension {
                    key: &pair[..equals],
                    value: &pair[equals + 1..],
                },
            ))
        })();
        Some(match record {
            Some((length, extension)) => {
                self.data = &data[length..];
                Ok(extension)
            }
            None => Err(other("malformed pax extension")),
        })
    }
}

impl<'entry> PaxExtension<'entry> {
    /// Returns the key for this key/value pair parsed as a string.
    ///
    /// May fail if the key isn't actually utf-8.
    pub fn key(&self) -> Result<&'entry str, str::Utf8Error> {
        str::from_utf8(self.key)
    }

    /// Returns the underlying raw bytes for the key of this key/value pair.
    pub fn key_bytes(&self) -> &'entry [u8] {
        self.key
    }

    /// Returns the value for this key/value pair parsed as a string.
    ///
    /// May fail if the value isn't actually utf-8.
    pub fn value(&self) -> Result<&'entry str, str::Utf8Error> {
        str::from_utf8(self.value)
    }

    /// Returns the underlying raw bytes for this value of this key/value pair.
    pub fn value_bytes(&self) -> &'entry [u8] {
        self.value
    }
}

/// Extension trait for `Builder` to append PAX extended headers.
impl<T: Write> crate::Builder<T> {
    /// Append PAX extended headers to the archive.
    ///
    /// Takes in an iterator over the list of headers to add to convert it into a header set formatted.
    ///
    /// Returns io::Error if an error occurs, else it returns ()
    pub fn append_pax_extensions<'key, 'value>(
        &mut self,
        headers: impl IntoIterator<Item = (&'key str, &'value [u8])>,
    ) -> Result<(), io::Error> {
        // Store the headers formatted before write
        let mut data: Vec<u8> = Vec::new();

        // For each key in headers, convert into a sized space and add it to data.
        // This will then be written in the file
        for (key, value) in headers {
            let mut len_len = 1;
            let mut max_len = 10;
            let rest_len = 3 + key.len() + value.len();
            while rest_len + len_len >= max_len {
                len_len += 1;
                max_len *= 10;
            }
            let len = rest_len + len_len;
            write!(&mut data, "{} {}=", len, key)?;
            data.extend_from_slice(value);
            data.push(b'\n');
        }

        // Ignore the header append if it's empty.
        if data.is_empty() {
            return Ok(());
        }

        // Create a header of type XHeader, set the size to the length of the
        // data, set the entry type to XHeader, and set the checksum
        // then append the header and the data to the archive.
        let mut header = crate::Header::new_ustar();
        let data_as_bytes: &[u8] = &data;
        header.set_size(data_as_bytes.len() as u64);
        header.set_entry_type(crate::EntryType::XHeader);
        header.set_cksum();
        self.append(&header, data_as_bytes)
    }
}

#[cfg(test)]
mod length_record_tests {
    use super::*;

    fn record(key: &str, value: &[u8]) -> Vec<u8> {
        let mut builder = crate::Builder::new(Vec::new());
        builder.append_pax_extensions([(key, value)]).unwrap();
        let bytes = builder.into_inner().unwrap();
        let size = crate::Header::from_byte_slice(&bytes[..512])
            .size()
            .unwrap() as usize;
        bytes[512..512 + size].to_vec()
    }

    #[test]
    fn newline_and_unicode_values_do_not_split_records() {
        let path = "a ; $(false) &?#+%\n雪.txt";
        let mut data = record("path", path.as_bytes());
        data.extend(record("size", b"25"));
        data.extend(record("linkpath", b"a\n b"));
        data.extend(record("comment", b""));
        let entries = PaxExtensions::new(&data)
            .map(|e| {
                let e = e.unwrap();
                (e.key_bytes().to_vec(), e.value_bytes().to_vec())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            vec![
                (b"path".to_vec(), path.as_bytes().to_vec()),
                (b"size".to_vec(), b"25".to_vec()),
                (b"linkpath".to_vec(), b"a\n b".to_vec()),
                (b"comment".to_vec(), Vec::new())
            ]
        );
        assert_eq!(pax_extensions_value(&data, "size"), Some(25));
    }

    #[test]
    fn invalid_lengths_fail_once_without_panicking_or_resynchronizing() {
        for bytes in [
            b"0 ".as_slice(),
            b"2 ",
            b"9 path=x",
            b"+9 path=x\n",
            b"9 =xxxxx\n",
            b"999999999999999999999999999 path=x\n",
            b"\n",
        ] {
            let mut entries = PaxExtensions::new(bytes);
            assert!(entries.next().unwrap().is_err(), "{bytes:?}");
            assert!(entries.next().is_none());
        }
    }

    #[test]
    fn unpack_uses_exact_pax_path_and_symlink_target() {
        let name = "雪\nfile.txt";
        let mut builder = crate::Builder::new(Vec::new());
        builder
            .append_pax_extensions([("path", name.as_bytes())])
            .unwrap();
        let mut header = crate::Header::new_ustar();
        header.set_path("fallback.txt").unwrap();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, b"hello".as_slice()).unwrap();
        builder
            .append_pax_extensions([("linkpath", name.as_bytes())])
            .unwrap();
        let mut header = crate::Header::new_ustar();
        header.set_path("link").unwrap();
        header.set_link_name("fallback.txt").unwrap();
        header.set_entry_type(crate::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_cksum();
        builder.append(&header, std::io::empty()).unwrap();
        let bytes = builder.into_inner().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let mut archive = crate::Archive::new(bytes.as_slice());
        #[cfg(unix)]
        {
            archive.unpack(directory.path()).unwrap();
            assert_eq!(
                std::fs::read_link(directory.path().join("link")).unwrap(),
                std::path::Path::new(name)
            );
        }
        #[cfg(not(unix))]
        {
            archive
                .entries()
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .unpack_in(directory.path())
                .unwrap();
        }
        assert_eq!(
            std::fs::read(directory.path().join(name)).unwrap(),
            b"hello"
        );
        assert!(!directory.path().join("fallback.txt").exists());
    }
}
