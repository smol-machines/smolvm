//! Mach-O binary manipulation for macOS code signing.
//!
//! This module provides functionality to:
//! - Parse Mach-O binaries
//! - Modify sections (write data into placeholder sections)
//! - Generate adhoc code signatures
//!
//! Based on the approach used by Bun: https://github.com/oven-sh/bun/pull/17207

#![allow(missing_docs)]

use std::io::{self, Read, Write};

/// Mach-O magic numbers
pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;

/// Load command types
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_DYLD_INFO_ONLY: u32 = 0x80000022;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x80000033;

/// Code signature magic
pub const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
pub const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
pub const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;

/// Code signature slot types (for BlobIndex)
pub const CSSLOT_CODEDIRECTORY: u32 = 0;
pub const CSSLOT_INFOSLOT: u32 = 1;
pub const CSSLOT_REQUIREMENTS: u32 = 2;

/// Code signature constants
pub const CS_ADHOC: u32 = 0x0002;
pub const CS_LINKER_SIGNED: u32 = 0x20000;
pub const CS_EXECSEG_MAIN_BINARY: u32 = 0x1;

/// Hash type for SHA256
pub const CS_HASHTYPE_SHA256: u8 = 2;
pub const CS_SHA256_LEN: usize = 32;

/// Page size for code signing (16KB on arm64)
pub const CS_PAGE_SIZE: usize = 16384;

/// Mach-O 64-bit header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MachHeader64 {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

impl MachHeader64 {
    pub const SIZE: usize = 32;

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            magic: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            cputype: i32::from_le_bytes(buf[4..8].try_into().unwrap()),
            cpusubtype: i32::from_le_bytes(buf[8..12].try_into().unwrap()),
            filetype: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            ncmds: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            sizeofcmds: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            reserved: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
        })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.magic.to_le_bytes())?;
        writer.write_all(&self.cputype.to_le_bytes())?;
        writer.write_all(&self.cpusubtype.to_le_bytes())?;
        writer.write_all(&self.filetype.to_le_bytes())?;
        writer.write_all(&self.ncmds.to_le_bytes())?;
        writer.write_all(&self.sizeofcmds.to_le_bytes())?;
        writer.write_all(&self.flags.to_le_bytes())?;
        writer.write_all(&self.reserved.to_le_bytes())?;
        Ok(())
    }
}

/// Load command header
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
}

impl LoadCommand {
    pub const SIZE: usize = 8;

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            cmd: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            cmdsize: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        })
    }
}

/// Segment command (64-bit)
#[derive(Debug, Clone)]
pub struct SegmentCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
}

impl SegmentCommand64 {
    pub const SIZE: usize = 72;

    pub fn read<R: Read>(reader: &mut R, cmd: u32, cmdsize: u32) -> io::Result<Self> {
        let mut buf = [0u8; Self::SIZE - 8]; // Exclude cmd and cmdsize
        reader.read_exact(&mut buf)?;

        let mut segname = [0u8; 16];
        segname.copy_from_slice(&buf[0..16]);

        Ok(Self {
            cmd,
            cmdsize,
            segname,
            vmaddr: u64::from_le_bytes(buf[16..24].try_into().unwrap()),
            vmsize: u64::from_le_bytes(buf[24..32].try_into().unwrap()),
            fileoff: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            filesize: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            maxprot: i32::from_le_bytes(buf[48..52].try_into().unwrap()),
            initprot: i32::from_le_bytes(buf[52..56].try_into().unwrap()),
            nsects: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
        })
    }

    pub fn name(&self) -> &str {
        let len = self.segname.iter().position(|&c| c == 0).unwrap_or(16);
        std::str::from_utf8(&self.segname[..len]).unwrap_or("")
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.cmd.to_le_bytes())?;
        writer.write_all(&self.cmdsize.to_le_bytes())?;
        writer.write_all(&self.segname)?;
        writer.write_all(&self.vmaddr.to_le_bytes())?;
        writer.write_all(&self.vmsize.to_le_bytes())?;
        writer.write_all(&self.fileoff.to_le_bytes())?;
        writer.write_all(&self.filesize.to_le_bytes())?;
        writer.write_all(&self.maxprot.to_le_bytes())?;
        writer.write_all(&self.initprot.to_le_bytes())?;
        writer.write_all(&self.nsects.to_le_bytes())?;
        writer.write_all(&self.flags.to_le_bytes())?;
        Ok(())
    }
}

/// Section (64-bit)
#[derive(Debug, Clone)]
pub struct Section64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

impl Section64 {
    pub const SIZE: usize = 80;

    pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact(&mut buf)?;

        let mut sectname = [0u8; 16];
        let mut segname = [0u8; 16];
        sectname.copy_from_slice(&buf[0..16]);
        segname.copy_from_slice(&buf[16..32]);

        Ok(Self {
            sectname,
            segname,
            addr: u64::from_le_bytes(buf[32..40].try_into().unwrap()),
            size: u64::from_le_bytes(buf[40..48].try_into().unwrap()),
            offset: u32::from_le_bytes(buf[48..52].try_into().unwrap()),
            align: u32::from_le_bytes(buf[52..56].try_into().unwrap()),
            reloff: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
            nreloc: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
            flags: u32::from_le_bytes(buf[64..68].try_into().unwrap()),
            reserved1: u32::from_le_bytes(buf[68..72].try_into().unwrap()),
            reserved2: u32::from_le_bytes(buf[72..76].try_into().unwrap()),
            reserved3: u32::from_le_bytes(buf[76..80].try_into().unwrap()),
        })
    }

    pub fn name(&self) -> &str {
        let len = self.sectname.iter().position(|&c| c == 0).unwrap_or(16);
        std::str::from_utf8(&self.sectname[..len]).unwrap_or("")
    }

    pub fn segment_name(&self) -> &str {
        let len = self.segname.iter().position(|&c| c == 0).unwrap_or(16);
        std::str::from_utf8(&self.segname[..len]).unwrap_or("")
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.sectname)?;
        writer.write_all(&self.segname)?;
        writer.write_all(&self.addr.to_le_bytes())?;
        writer.write_all(&self.size.to_le_bytes())?;
        writer.write_all(&self.offset.to_le_bytes())?;
        writer.write_all(&self.align.to_le_bytes())?;
        writer.write_all(&self.reloff.to_le_bytes())?;
        writer.write_all(&self.nreloc.to_le_bytes())?;
        writer.write_all(&self.flags.to_le_bytes())?;
        writer.write_all(&self.reserved1.to_le_bytes())?;
        writer.write_all(&self.reserved2.to_le_bytes())?;
        writer.write_all(&self.reserved3.to_le_bytes())?;
        Ok(())
    }
}

/// Code signature linkedit data command
#[derive(Debug, Clone, Copy)]
pub struct LinkeditDataCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

impl LinkeditDataCommand {
    pub const SIZE: usize = 16;

    pub fn read<R: Read>(reader: &mut R, cmd: u32, cmdsize: u32) -> io::Result<Self> {
        let mut buf = [0u8; 8];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            cmd,
            cmdsize,
            dataoff: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            datasize: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
        })
    }

    pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
        writer.write_all(&self.cmd.to_le_bytes())?;
        writer.write_all(&self.cmdsize.to_le_bytes())?;
        writer.write_all(&self.dataoff.to_le_bytes())?;
        writer.write_all(&self.datasize.to_le_bytes())?;
        Ok(())
    }
}

/// Symtab command
#[derive(Debug, Clone, Copy)]
pub struct SymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

impl SymtabCommand {
    pub fn read<R: Read>(reader: &mut R, cmd: u32, cmdsize: u32) -> io::Result<Self> {
        let mut buf = [0u8; 16];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            cmd,
            cmdsize,
            symoff: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            nsyms: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            stroff: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            strsize: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
        })
    }
}

/// Dysymtab command
#[derive(Debug, Clone, Copy)]
pub struct DysymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

impl DysymtabCommand {
    pub fn read<R: Read>(reader: &mut R, cmd: u32, cmdsize: u32) -> io::Result<Self> {
        let mut buf = [0u8; 72];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            cmd,
            cmdsize,
            ilocalsym: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            nlocalsym: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            iextdefsym: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            nextdefsym: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            iundefsym: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            nundefsym: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            tocoff: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            ntoc: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
            modtaboff: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            nmodtab: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
            extrefsymoff: u32::from_le_bytes(buf[40..44].try_into().unwrap()),
            nextrefsyms: u32::from_le_bytes(buf[44..48].try_into().unwrap()),
            indirectsymoff: u32::from_le_bytes(buf[48..52].try_into().unwrap()),
            nindirectsyms: u32::from_le_bytes(buf[52..56].try_into().unwrap()),
            extreloff: u32::from_le_bytes(buf[56..60].try_into().unwrap()),
            nextrel: u32::from_le_bytes(buf[60..64].try_into().unwrap()),
            locreloff: u32::from_le_bytes(buf[64..68].try_into().unwrap()),
            nlocrel: u32::from_le_bytes(buf[68..72].try_into().unwrap()),
        })
    }
}

/// DyldInfo command (LC_DYLD_INFO or LC_DYLD_INFO_ONLY)
#[derive(Debug, Clone, Copy)]
pub struct DyldInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

impl DyldInfoCommand {
    pub fn read<R: Read>(reader: &mut R, cmd: u32, cmdsize: u32) -> io::Result<Self> {
        let mut buf = [0u8; 40];
        reader.read_exact(&mut buf)?;
        Ok(Self {
            cmd,
            cmdsize,
            rebase_off: u32::from_le_bytes(buf[0..4].try_into().unwrap()),
            rebase_size: u32::from_le_bytes(buf[4..8].try_into().unwrap()),
            bind_off: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
            bind_size: u32::from_le_bytes(buf[12..16].try_into().unwrap()),
            weak_bind_off: u32::from_le_bytes(buf[16..20].try_into().unwrap()),
            weak_bind_size: u32::from_le_bytes(buf[20..24].try_into().unwrap()),
            lazy_bind_off: u32::from_le_bytes(buf[24..28].try_into().unwrap()),
            lazy_bind_size: u32::from_le_bytes(buf[28..32].try_into().unwrap()),
            export_off: u32::from_le_bytes(buf[32..36].try_into().unwrap()),
            export_size: u32::from_le_bytes(buf[36..40].try_into().unwrap()),
        })
    }
}

/// Parsed load command with data
#[derive(Debug)]
pub enum ParsedLoadCommand {
    Segment64 {
        segment: SegmentCommand64,
        sections: Vec<Section64>,
    },
    CodeSignature(LinkeditDataCommand),
    FunctionStarts(LinkeditDataCommand),
    DataInCode(LinkeditDataCommand),
    DyldChainedFixups(LinkeditDataCommand),
    DyldExportsTrie(LinkeditDataCommand),
    Symtab(SymtabCommand),
    Dysymtab(DysymtabCommand),
    DyldInfo(DyldInfoCommand),
    Other {
        cmd: u32,
        data: Vec<u8>,
    },
}

/// Mach-O file for manipulation
pub struct MachoFile {
    pub header: MachHeader64,
    pub load_commands: Vec<ParsedLoadCommand>,
    /// File data after load commands
    pub file_data: Vec<u8>,
    /// Offset where file_data starts
    pub data_offset: usize,
}

impl MachoFile {
    /// Parse a Mach-O file from bytes
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        let mut cursor = std::io::Cursor::new(data);

        // Read header
        let header = MachHeader64::read(&mut cursor)?;
        if header.magic != MH_MAGIC_64 && header.magic != MH_CIGAM_64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid Mach-O magic: 0x{:x}", header.magic),
            ));
        }

        // Read load commands. Cap the pre-allocation by the byte budget (each
        // command is at least LoadCommand::SIZE), so a bogus `ncmds` can't demand
        // a huge allocation before a single byte is validated.
        let mut load_commands =
            Vec::with_capacity((header.ncmds as usize).min(data.len() / LoadCommand::SIZE + 1));
        for _ in 0..header.ncmds {
            let cmd_start = cursor.position() as usize;
            let lc = LoadCommand::read(&mut cursor)?;

            // Validate the declared command size before trusting it: at least its
            // own 8-byte header (a smaller value underflows `cmdsize - SIZE` below
            // into an enormous allocation) and within the file (so the fallback
            // `vec![0u8; remaining]` and `set_position` stay bounded by the input).
            let cmd_end = cmd_start.checked_add(lc.cmdsize as usize);
            if (lc.cmdsize as usize) < LoadCommand::SIZE
                || cmd_end.is_none_or(|end| end > data.len())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "malformed Mach-O load command 0x{:x}: cmdsize {}",
                        lc.cmd, lc.cmdsize
                    ),
                ));
            }

            let parsed = match lc.cmd {
                LC_SEGMENT_64 => {
                    let segment = SegmentCommand64::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    // Cap by the byte budget: `nsects` is attacker-controlled and
                    // each section is Section64::SIZE bytes, so an inflated count
                    // must not drive the pre-allocation.
                    let mut sections = Vec::with_capacity(
                        (segment.nsects as usize).min(data.len() / Section64::SIZE + 1),
                    );
                    for _ in 0..segment.nsects {
                        sections.push(Section64::read(&mut cursor)?);
                    }
                    ParsedLoadCommand::Segment64 { segment, sections }
                }
                LC_CODE_SIGNATURE => {
                    let cmd = LinkeditDataCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::CodeSignature(cmd)
                }
                LC_FUNCTION_STARTS => {
                    let cmd = LinkeditDataCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::FunctionStarts(cmd)
                }
                LC_DATA_IN_CODE => {
                    let cmd = LinkeditDataCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::DataInCode(cmd)
                }
                LC_DYLD_CHAINED_FIXUPS => {
                    let cmd = LinkeditDataCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::DyldChainedFixups(cmd)
                }
                LC_DYLD_EXPORTS_TRIE => {
                    let cmd = LinkeditDataCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::DyldExportsTrie(cmd)
                }
                LC_SYMTAB => {
                    let cmd = SymtabCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::Symtab(cmd)
                }
                LC_DYSYMTAB => {
                    let cmd = DysymtabCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::Dysymtab(cmd)
                }
                LC_DYLD_INFO_ONLY => {
                    let cmd = DyldInfoCommand::read(&mut cursor, lc.cmd, lc.cmdsize)?;
                    ParsedLoadCommand::DyldInfo(cmd)
                }
                _ => {
                    // Read remaining bytes for this command
                    let remaining = lc.cmdsize as usize - LoadCommand::SIZE;
                    let mut cmd_data = vec![0u8; remaining];
                    cursor.read_exact(&mut cmd_data)?;
                    ParsedLoadCommand::Other {
                        cmd: lc.cmd,
                        data: cmd_data,
                    }
                }
            };

            // Ensure we're at the right position
            let expected_end = cmd_start + lc.cmdsize as usize;
            cursor.set_position(expected_end as u64);

            load_commands.push(parsed);
        }

        let data_offset = cursor.position() as usize;
        let file_data = data[data_offset..].to_vec();

        Ok(Self {
            header,
            load_commands,
            file_data,
            data_offset,
        })
    }

    /// Find a section by segment and section name
    pub fn find_section(&self, seg_name: &str, sect_name: &str) -> Option<(&Section64, usize)> {
        for (cmd_idx, cmd) in self.load_commands.iter().enumerate() {
            if let ParsedLoadCommand::Segment64 { sections, .. } = cmd {
                for section in sections {
                    if section.segment_name() == seg_name && section.name() == sect_name {
                        return Some((section, cmd_idx));
                    }
                }
            }
        }
        None
    }

    /// Find the __LINKEDIT segment
    pub fn find_linkedit(&self) -> Option<&SegmentCommand64> {
        for cmd in &self.load_commands {
            if let ParsedLoadCommand::Segment64 { segment, .. } = cmd {
                if segment.name() == "__LINKEDIT" {
                    return Some(segment);
                }
            }
        }
        None
    }

    /// Get code signature command if present
    pub fn code_signature(&self) -> Option<&LinkeditDataCommand> {
        for cmd in &self.load_commands {
            if let ParsedLoadCommand::CodeSignature(cs) = cmd {
                return Some(cs);
            }
        }
        None
    }

    /// Align a value up to the page size boundary (16KB for arm64).
    fn page_align(size: usize) -> usize {
        (size + CS_PAGE_SIZE - 1) & !(CS_PAGE_SIZE - 1)
    }

    /// Write data into a section, expanding the binary as needed.
    ///
    /// This is designed for sections in their own dedicated segment (like __SMOLVM).
    /// It updates the section size, segment sizes, and all file offsets for content
    /// that follows in the binary.
    pub fn write_section(
        &mut self,
        seg_name: &str,
        sect_name: &str,
        data: &[u8],
    ) -> io::Result<()> {
        // Find the section
        let (section_offset, old_size, cmd_idx, sect_idx) = self
            .find_section_details(seg_name, sect_name)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Section ({},{}) not found", seg_name, sect_name),
                )
            })?;

        let new_size = data.len();
        let aligned_new_size = Self::page_align(new_size);

        // Calculate the page-aligned delta for shifting subsequent content.
        // The delta must be page-aligned so LINKEDIT remains at a page boundary.
        let delta = if aligned_new_size > old_size {
            Self::page_align(aligned_new_size - old_size) as i64
        } else {
            -(Self::page_align(old_size - aligned_new_size) as i64)
        };

        // Modify file_data: expand or contract at the section location
        let relative_offset = section_offset - self.data_offset;
        self.resize_file_data(relative_offset, old_size, aligned_new_size, delta);

        // Write the actual data and zero-pad to alignment
        self.file_data[relative_offset..relative_offset + new_size].copy_from_slice(data);
        for byte in
            &mut self.file_data[relative_offset + new_size..relative_offset + aligned_new_size]
        {
            *byte = 0;
        }

        // Update section and segment metadata
        let segment_vmaddr =
            self.update_segment_for_section(cmd_idx, sect_idx, aligned_new_size as u64, delta);

        // Shift all content after this section
        if delta != 0 {
            self.shift_offsets_after(section_offset + old_size, segment_vmaddr, delta);
        }

        Ok(())
    }

    /// Find section details: (file_offset, size, cmd_index, section_index).
    fn find_section_details(
        &self,
        seg_name: &str,
        sect_name: &str,
    ) -> Option<(usize, usize, usize, usize)> {
        for (cmd_idx, cmd) in self.load_commands.iter().enumerate() {
            if let ParsedLoadCommand::Segment64 { sections, .. } = cmd {
                for (sect_idx, section) in sections.iter().enumerate() {
                    if section.segment_name() == seg_name && section.name() == sect_name {
                        return Some((
                            section.offset as usize,
                            section.size as usize,
                            cmd_idx,
                            sect_idx,
                        ));
                    }
                }
            }
        }
        None
    }

    /// Resize file_data by inserting or removing bytes at the given position.
    fn resize_file_data(
        &mut self,
        relative_offset: usize,
        old_size: usize,
        new_size: usize,
        delta: i64,
    ) {
        if delta > 0 {
            // Expand: insert bytes after old content
            let insert_pos = relative_offset + old_size;
            self.file_data
                .splice(insert_pos..insert_pos, vec![0u8; delta as usize]);
        } else if delta < 0 {
            // Shrink: remove bytes
            let remove_start = relative_offset + new_size;
            let remove_end = relative_offset + old_size;
            if remove_end > remove_start {
                self.file_data.drain(remove_start..remove_end);
            }
        }
    }

    /// Update segment and section metadata after resizing a section.
    /// Returns the segment's vmaddr for use in shifting subsequent segments.
    fn update_segment_for_section(
        &mut self,
        cmd_idx: usize,
        sect_idx: usize,
        new_section_size: u64,
        delta: i64,
    ) -> u64 {
        if let ParsedLoadCommand::Segment64 { segment, sections } = &mut self.load_commands[cmd_idx]
        {
            let section_addr = sections[sect_idx].addr;
            let old_vmsize = segment.vmsize;

            // Update section size
            sections[sect_idx].size = new_section_size;

            // Update segment file size
            segment.filesize = (segment.filesize as i64 + delta) as u64;

            // Calculate required vmsize to contain the section
            let section_offset_in_segment = section_addr - segment.vmaddr;
            let required_vmsize = section_offset_in_segment + new_section_size;
            let aligned_vmsize = Self::page_align(required_vmsize as usize) as u64;

            segment.vmsize = std::cmp::max((old_vmsize as i64 + delta) as u64, aligned_vmsize);

            segment.vmaddr
        } else {
            0
        }
    }

    /// Shift file offsets and vmaddrs for all content after the modification point.
    fn shift_offsets_after(&mut self, after_offset: usize, modified_vmaddr: u64, delta: i64) {
        for cmd in &mut self.load_commands {
            match cmd {
                ParsedLoadCommand::Segment64 { segment, sections } => {
                    let is_modified = segment.vmaddr == modified_vmaddr;
                    let should_move = segment.vmaddr > modified_vmaddr && segment.vmaddr != 0;

                    // Shift segment file offset
                    if segment.fileoff as usize > after_offset {
                        segment.fileoff = (segment.fileoff as i64 + delta) as u64;
                    }

                    // Shift segment vmaddr for segments after the modified one
                    if should_move {
                        segment.vmaddr = (segment.vmaddr as i64 + delta) as u64;
                    }

                    // Shift sections (skip the modified segment - already handled)
                    if !is_modified {
                        for section in sections {
                            if section.offset as usize > after_offset {
                                section.offset = (section.offset as i64 + delta) as u32;
                            }
                            if should_move {
                                section.addr = (section.addr as i64 + delta) as u64;
                            }
                        }
                    }
                }
                ParsedLoadCommand::CodeSignature(lc)
                | ParsedLoadCommand::FunctionStarts(lc)
                | ParsedLoadCommand::DataInCode(lc)
                | ParsedLoadCommand::DyldChainedFixups(lc)
                | ParsedLoadCommand::DyldExportsTrie(lc) => {
                    if lc.dataoff as usize > after_offset {
                        lc.dataoff = (lc.dataoff as i64 + delta) as u32;
                    }
                }
                ParsedLoadCommand::Symtab(st) => {
                    Self::shift_offset_if_after(&mut st.symoff, after_offset, delta);
                    Self::shift_offset_if_after(&mut st.stroff, after_offset, delta);
                }
                ParsedLoadCommand::Dysymtab(dst) => {
                    Self::shift_offset_if_after(&mut dst.tocoff, after_offset, delta);
                    Self::shift_offset_if_after(&mut dst.modtaboff, after_offset, delta);
                    Self::shift_offset_if_after(&mut dst.extrefsymoff, after_offset, delta);
                    Self::shift_offset_if_after(&mut dst.indirectsymoff, after_offset, delta);
                    Self::shift_offset_if_after(&mut dst.extreloff, after_offset, delta);
                    Self::shift_offset_if_after(&mut dst.locreloff, after_offset, delta);
                }
                ParsedLoadCommand::DyldInfo(di) => {
                    Self::shift_offset_if_after(&mut di.rebase_off, after_offset, delta);
                    Self::shift_offset_if_after(&mut di.bind_off, after_offset, delta);
                    Self::shift_offset_if_after(&mut di.weak_bind_off, after_offset, delta);
                    Self::shift_offset_if_after(&mut di.lazy_bind_off, after_offset, delta);
                    Self::shift_offset_if_after(&mut di.export_off, after_offset, delta);
                }
                ParsedLoadCommand::Other { .. } => {}
            }
        }
    }

    /// Helper to shift an offset if it's after the given position and non-zero.
    fn shift_offset_if_after(offset: &mut u32, after: usize, delta: i64) {
        if *offset != 0 && (*offset as usize) > after {
            *offset = (*offset as i64 + delta) as u32;
        }
    }

    /// Generate and embed an adhoc code signature
    pub fn sign_adhoc(&mut self) -> io::Result<()> {
        use sha2::{Digest, Sha256};

        // Remove existing code signature if present
        let mut cs_idx = None;
        for (i, cmd) in self.load_commands.iter().enumerate() {
            if matches!(cmd, ParsedLoadCommand::CodeSignature(_)) {
                cs_idx = Some(i);
                break;
            }
        }

        // If there's an existing signature, remove it from file_data
        if let Some(idx) = cs_idx {
            if let ParsedLoadCommand::CodeSignature(old_cs) = &self.load_commands[idx] {
                let sig_offset = old_cs.dataoff as usize;
                if sig_offset >= self.data_offset
                    && sig_offset < self.data_offset + self.file_data.len()
                {
                    let relative = sig_offset - self.data_offset;
                    self.file_data.truncate(relative);
                }
            }
            // Keep the load command, we'll update it
        }

        let code_size = self.data_offset + self.file_data.len();
        let code_size_aligned = (code_size + CS_PAGE_SIZE - 1) & !(CS_PAGE_SIZE - 1);

        // Pad file_data to page alignment
        let padding_needed = code_size_aligned - code_size;
        self.file_data.extend(vec![0u8; padding_needed]);

        // Calculate signature offset (after padded code)
        let sig_offset = self.data_offset + self.file_data.len();

        // Build the code signature parameters
        let identifier = b"smolvm-packed\0";
        let num_pages = code_size_aligned.div_ceil(CS_PAGE_SIZE);

        // Calculate sizes (version 0x20100 format = 48 bytes header)
        let cd_hash_offset = 48; // CodeDirectory header size for version 0x20100
        let cd_ident_offset = cd_hash_offset + (num_pages * CS_SHA256_LEN);
        let cd_size = cd_ident_offset + identifier.len();
        let cd_size_aligned = (cd_size + 3) & !3; // 4-byte align

        // SuperBlob header (12 bytes) + 1 blob index (8 bytes) + CodeDirectory
        let sig_size = 12 + 8 + cd_size_aligned;
        let sig_size_aligned = (sig_size + 15) & !15; // 16-byte align

        // IMPORTANT: Update load commands BEFORE hashing so the hash matches what we write
        let new_cs = LinkeditDataCommand {
            cmd: LC_CODE_SIGNATURE,
            cmdsize: LinkeditDataCommand::SIZE as u32,
            dataoff: sig_offset as u32,
            datasize: sig_size_aligned as u32,
        };

        if let Some(idx) = cs_idx {
            self.load_commands[idx] = ParsedLoadCommand::CodeSignature(new_cs);
        } else {
            self.load_commands
                .push(ParsedLoadCommand::CodeSignature(new_cs));
            self.header.ncmds += 1;
            self.header.sizeofcmds += LinkeditDataCommand::SIZE as u32;
        }

        // Update __LINKEDIT segment to include the signature
        for cmd in &mut self.load_commands {
            if let ParsedLoadCommand::Segment64 { segment, .. } = cmd {
                if segment.name() == "__LINKEDIT" {
                    let linkedit_end = sig_offset + sig_size_aligned;
                    segment.filesize = (linkedit_end - segment.fileoff as usize) as u64;
                    segment.vmsize =
                        (segment.filesize + CS_PAGE_SIZE as u64 - 1) & !(CS_PAGE_SIZE as u64 - 1);
                    break;
                }
            }
        }

        // Now build binary for hashing (with updated load commands, but without signature data)
        let full_binary = self.build_binary_for_hashing(code_size_aligned);

        // Build CodeDirectory header
        let mut code_directory = Vec::with_capacity(cd_size_aligned);

        // CodeDirectory header (version 0x20100 format - 48 bytes)
        code_directory.extend(&CSMAGIC_CODEDIRECTORY.to_be_bytes()); // magic
        code_directory.extend(&(cd_size as u32).to_be_bytes()); // length
        code_directory.extend(&0x20100u32.to_be_bytes()); // version (use 0x20100 for simpler format)
        code_directory.extend(&CS_ADHOC.to_be_bytes()); // flags
        code_directory.extend(&(cd_hash_offset as u32).to_be_bytes()); // hashOffset
        code_directory.extend(&(cd_ident_offset as u32).to_be_bytes()); // identOffset
        code_directory.extend(&0u32.to_be_bytes()); // nSpecialSlots
        code_directory.extend(&(num_pages as u32).to_be_bytes()); // nCodeSlots
        code_directory.extend(&(code_size_aligned as u32).to_be_bytes()); // codeLimit
        code_directory.push(CS_SHA256_LEN as u8); // hashSize (32 for SHA256)
        code_directory.push(CS_HASHTYPE_SHA256); // hashType
        code_directory.push(0); // platform
        code_directory.push(14); // pageSize (log2 of 16384 = 14)
        code_directory.extend(&0u32.to_be_bytes()); // spare2
        code_directory.extend(&0u32.to_be_bytes()); // scatterOffset (version 0x20100)

        // Hash each page
        for page_idx in 0..num_pages {
            let page_start = page_idx * CS_PAGE_SIZE;
            let page_end = std::cmp::min(page_start + CS_PAGE_SIZE, full_binary.len());
            let page_data = &full_binary[page_start..page_end];

            let mut hasher = Sha256::new();
            hasher.update(page_data);
            let hash = hasher.finalize();
            code_directory.extend(&hash[..]);
        }

        // Identifier
        code_directory.extend(identifier);

        // Pad to alignment
        while code_directory.len() < cd_size_aligned {
            code_directory.push(0);
        }

        // Build SuperBlob
        let mut signature = Vec::with_capacity(sig_size_aligned);
        signature.extend(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes()); // magic
        signature.extend(&(sig_size as u32).to_be_bytes()); // length
        signature.extend(&1u32.to_be_bytes()); // count (1 blob)

        // Blob index for CodeDirectory
        signature.extend(&CSSLOT_CODEDIRECTORY.to_be_bytes()); // type (slot type, not magic)
        signature.extend(&20u32.to_be_bytes()); // offset (after superblob header + index)

        // CodeDirectory blob
        signature.extend(&code_directory);

        // Pad to alignment
        while signature.len() < sig_size_aligned {
            signature.push(0);
        }

        // Append signature to file_data
        self.file_data.extend(&signature);

        Ok(())
    }

    /// Build binary data for hashing (header + load commands + file data)
    fn build_binary_for_hashing(&self, total_size: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(total_size);

        // Write header
        let mut header_buf = Vec::new();
        self.header.write(&mut header_buf).unwrap();
        result.extend(&header_buf);

        // Write load commands
        for cmd in &self.load_commands {
            self.write_load_command(&mut result, cmd);
        }

        // Pad to data_offset
        while result.len() < self.data_offset {
            result.push(0);
        }

        // Write file data (up to total_size)
        let data_to_write = std::cmp::min(self.file_data.len(), total_size - self.data_offset);
        result.extend(&self.file_data[..data_to_write]);

        // Pad to total size
        while result.len() < total_size {
            result.push(0);
        }

        result
    }

    fn write_load_command(&self, out: &mut Vec<u8>, cmd: &ParsedLoadCommand) {
        match cmd {
            ParsedLoadCommand::Segment64 { segment, sections } => {
                segment.write(out).unwrap();
                for section in sections {
                    section.write(out).unwrap();
                }
            }
            ParsedLoadCommand::CodeSignature(lc)
            | ParsedLoadCommand::FunctionStarts(lc)
            | ParsedLoadCommand::DataInCode(lc)
            | ParsedLoadCommand::DyldChainedFixups(lc)
            | ParsedLoadCommand::DyldExportsTrie(lc) => {
                lc.write(out).unwrap();
            }
            ParsedLoadCommand::Symtab(st) => {
                out.extend(&st.cmd.to_le_bytes());
                out.extend(&st.cmdsize.to_le_bytes());
                out.extend(&st.symoff.to_le_bytes());
                out.extend(&st.nsyms.to_le_bytes());
                out.extend(&st.stroff.to_le_bytes());
                out.extend(&st.strsize.to_le_bytes());
            }
            ParsedLoadCommand::Dysymtab(dst) => {
                out.extend(&dst.cmd.to_le_bytes());
                out.extend(&dst.cmdsize.to_le_bytes());
                out.extend(&dst.ilocalsym.to_le_bytes());
                out.extend(&dst.nlocalsym.to_le_bytes());
                out.extend(&dst.iextdefsym.to_le_bytes());
                out.extend(&dst.nextdefsym.to_le_bytes());
                out.extend(&dst.iundefsym.to_le_bytes());
                out.extend(&dst.nundefsym.to_le_bytes());
                out.extend(&dst.tocoff.to_le_bytes());
                out.extend(&dst.ntoc.to_le_bytes());
                out.extend(&dst.modtaboff.to_le_bytes());
                out.extend(&dst.nmodtab.to_le_bytes());
                out.extend(&dst.extrefsymoff.to_le_bytes());
                out.extend(&dst.nextrefsyms.to_le_bytes());
                out.extend(&dst.indirectsymoff.to_le_bytes());
                out.extend(&dst.nindirectsyms.to_le_bytes());
                out.extend(&dst.extreloff.to_le_bytes());
                out.extend(&dst.nextrel.to_le_bytes());
                out.extend(&dst.locreloff.to_le_bytes());
                out.extend(&dst.nlocrel.to_le_bytes());
            }
            ParsedLoadCommand::DyldInfo(di) => {
                out.extend(&di.cmd.to_le_bytes());
                out.extend(&di.cmdsize.to_le_bytes());
                out.extend(&di.rebase_off.to_le_bytes());
                out.extend(&di.rebase_size.to_le_bytes());
                out.extend(&di.bind_off.to_le_bytes());
                out.extend(&di.bind_size.to_le_bytes());
                out.extend(&di.weak_bind_off.to_le_bytes());
                out.extend(&di.weak_bind_size.to_le_bytes());
                out.extend(&di.lazy_bind_off.to_le_bytes());
                out.extend(&di.lazy_bind_size.to_le_bytes());
                out.extend(&di.export_off.to_le_bytes());
                out.extend(&di.export_size.to_le_bytes());
            }
            ParsedLoadCommand::Other { cmd, data } => {
                out.extend(&cmd.to_le_bytes());
                out.extend(&((data.len() + 8) as u32).to_le_bytes());
                out.extend(data);
            }
        }
    }

    /// Write the Mach-O file to bytes
    pub fn write(&self) -> Vec<u8> {
        let mut result = Vec::new();

        // Write header
        self.header.write(&mut result).unwrap();

        // Write load commands
        for cmd in &self.load_commands {
            self.write_load_command(&mut result, cmd);
        }

        // Pad to data_offset if needed
        while result.len() < self.data_offset {
            result.push(0);
        }

        // Write file data
        result.extend(&self.file_data);

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_stub() {
        // This test requires the actual stub binary
        let stub_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/release/smolvm");
        if let Ok(data) = std::fs::read(stub_path) {
            let macho = MachoFile::parse(&data).expect("Failed to parse Mach-O");
            assert_eq!(macho.header.magic, MH_MAGIC_64);

            // Check we found some segments
            let mut found_text = false;
            let mut found_data = false;
            for cmd in &macho.load_commands {
                if let ParsedLoadCommand::Segment64 { segment, .. } = cmd {
                    if segment.name() == "__TEXT" {
                        found_text = true;
                    }
                    if segment.name() == "__DATA" {
                        found_data = true;
                    }
                }
            }
            assert!(found_text, "Should find __TEXT segment");
            assert!(found_data, "Should find __DATA segment");
        }
    }

    #[test]
    fn test_write_section_and_sign() {
        // This test requires the actual stub binary with the __smolvm section
        let stub_path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/release/smolvm");
        let data = match std::fs::read(stub_path) {
            Ok(d) => d,
            Err(_) => return, // Skip if stub not built
        };

        let mut macho = match MachoFile::parse(&data) {
            Ok(m) => m,
            Err(_) => return, // Skip if not a valid Mach-O
        };

        // Check if section exists
        if macho.find_section("__SMOLVM", "__smolvm").is_none() {
            return; // Skip if section not present
        }

        // Write test data to section
        let test_data = b"SMOLSECT\x00\x00\x00\x00\x00\x00\x00\x00test data for section";
        macho
            .write_section("__SMOLVM", "__smolvm", test_data)
            .expect("Failed to write section");

        // Sign adhoc
        macho.sign_adhoc().expect("Failed to sign");

        // Write to temp file at a known location for debugging
        let output_path = std::path::PathBuf::from("/tmp/test-signed-stub");
        let output_data = macho.write();
        std::fs::write(&output_path, &output_data).unwrap();

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&output_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&output_path, perms).unwrap();
        }

        // Check with otool first to see load commands
        let otool_output = std::process::Command::new("otool")
            .args(["-l"])
            .arg(&output_path)
            .output()
            .expect("Failed to run otool");
        let otool_str = String::from_utf8_lossy(&otool_output.stdout);

        // Check if LC_CODE_SIGNATURE is present
        assert!(
            otool_str.contains("LC_CODE_SIGNATURE"),
            "LC_CODE_SIGNATURE not found in output. Output at /tmp/test-signed-stub. otool output:\n{}",
            otool_str
        );

        // Verify with codesign
        let output = std::process::Command::new("codesign")
            .args(["-v", "--verbose"])
            .arg(&output_path)
            .output()
            .expect("Failed to run codesign");

        // codesign -v returns 0 for valid signatures
        assert!(
            output.status.success(),
            "Code signature verification failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_header_roundtrip() {
        let header = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: 0x0100000c, // ARM64
            cpusubtype: 0,
            filetype: 2, // MH_EXECUTE
            ncmds: 10,
            sizeofcmds: 1000,
            flags: 0,
            reserved: 0,
        };

        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();

        let mut cursor = std::io::Cursor::new(&buf);
        let parsed = MachHeader64::read(&mut cursor).unwrap();

        assert_eq!(header.magic, parsed.magic);
        assert_eq!(header.cputype, parsed.cputype);
        assert_eq!(header.ncmds, parsed.ncmds);
    }

    fn header_with_one_cmd() -> Vec<u8> {
        let header = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: 0x0100000c, // ARM64
            cpusubtype: 0,
            filetype: 2, // MH_EXECUTE
            ncmds: 1,
            sizeofcmds: 0,
            flags: 0,
            reserved: 0,
        };
        let mut buf = Vec::new();
        header.write(&mut buf).unwrap();
        buf
    }

    // A load command claiming cmdsize < its own 8-byte header would underflow
    // `cmdsize - SIZE` into an enormous allocation; parse must reject it cleanly
    // so the packer's "not a Mach-O, fall back" path works instead of aborting.
    #[test]
    fn parse_rejects_undersized_load_command() {
        let mut buf = header_with_one_cmd();
        buf.extend_from_slice(&0x99u32.to_le_bytes()); // unknown cmd
        buf.extend_from_slice(&4u32.to_le_bytes()); // cmdsize = 4 (< 8)
        assert!(MachoFile::parse(&buf).is_err());
    }

    // A cmdsize that runs past the end of the file must error rather than drive a
    // multi-gigabyte `vec![0u8; cmdsize - SIZE]` allocation.
    #[test]
    fn parse_rejects_out_of_bounds_cmdsize() {
        let mut buf = header_with_one_cmd();
        buf.extend_from_slice(&0x99u32.to_le_bytes()); // unknown cmd
        buf.extend_from_slice(&u32::MAX.to_le_bytes()); // cmdsize ~4 GiB, no data
        assert!(MachoFile::parse(&buf).is_err());
    }

    #[test]
    fn test_page_align() {
        // Test exact page boundaries
        assert_eq!(MachoFile::page_align(0), 0);
        assert_eq!(MachoFile::page_align(CS_PAGE_SIZE), CS_PAGE_SIZE);
        assert_eq!(MachoFile::page_align(CS_PAGE_SIZE * 2), CS_PAGE_SIZE * 2);

        // Test rounding up
        assert_eq!(MachoFile::page_align(1), CS_PAGE_SIZE);
        assert_eq!(MachoFile::page_align(100), CS_PAGE_SIZE);
        assert_eq!(MachoFile::page_align(CS_PAGE_SIZE - 1), CS_PAGE_SIZE);
        assert_eq!(MachoFile::page_align(CS_PAGE_SIZE + 1), CS_PAGE_SIZE * 2);
    }

    #[test]
    fn test_shift_offset_if_after() {
        // Test: offset is after threshold, should shift
        let mut offset = 1000u32;
        MachoFile::shift_offset_if_after(&mut offset, 500, 100);
        assert_eq!(offset, 1100);

        // Test: offset is before threshold, should not shift
        let mut offset = 400u32;
        MachoFile::shift_offset_if_after(&mut offset, 500, 100);
        assert_eq!(offset, 400);

        // Test: offset is zero, should not shift (zero means unused)
        let mut offset = 0u32;
        MachoFile::shift_offset_if_after(&mut offset, 0, 100);
        assert_eq!(offset, 0);

        // Test: negative delta (shrinking)
        let mut offset = 1000u32;
        MachoFile::shift_offset_if_after(&mut offset, 500, -100);
        assert_eq!(offset, 900);
    }

    #[test]
    fn test_segment_name() {
        let mut segname = [0u8; 16];
        segname[..8].copy_from_slice(b"__TEXT\0\0");

        let segment = SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: 72,
            segname,
            vmaddr: 0,
            vmsize: 0,
            fileoff: 0,
            filesize: 0,
            maxprot: 0,
            initprot: 0,
            nsects: 0,
            flags: 0,
        };

        assert_eq!(segment.name(), "__TEXT");
    }

    #[test]
    fn test_section_name() {
        let mut sectname = [0u8; 16];
        let mut segname = [0u8; 16];
        sectname[..6].copy_from_slice(b"__text");
        segname[..8].copy_from_slice(b"__TEXT\0\0");

        let section = Section64 {
            sectname,
            segname,
            addr: 0,
            size: 0,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        };

        assert_eq!(section.name(), "__text");
        assert_eq!(section.segment_name(), "__TEXT");
    }

    #[test]
    fn test_load_command_roundtrip() {
        let lc = LinkeditDataCommand {
            cmd: LC_CODE_SIGNATURE,
            cmdsize: 16,
            dataoff: 12345,
            datasize: 6789,
        };

        let mut buf = Vec::new();
        lc.write(&mut buf).unwrap();

        assert_eq!(buf.len(), LinkeditDataCommand::SIZE);

        // Parse it back
        let cmd = u32::from_le_bytes(buf[0..4].try_into().unwrap());
        let dataoff = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        let datasize = u32::from_le_bytes(buf[12..16].try_into().unwrap());

        assert_eq!(cmd, LC_CODE_SIGNATURE);
        assert_eq!(dataoff, 12345);
        assert_eq!(datasize, 6789);
    }

    #[test]
    fn test_segment_command_roundtrip() {
        let mut segname = [0u8; 16];
        segname[..8].copy_from_slice(b"__SMOLVM");

        let segment = SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: 72,
            segname,
            vmaddr: 0x100000000,
            vmsize: 0x4000,
            fileoff: 0x8000,
            filesize: 0x1000,
            maxprot: 7,
            initprot: 3,
            nsects: 1,
            flags: 0,
        };

        let mut buf = Vec::new();
        segment.write(&mut buf).unwrap();

        assert_eq!(buf.len(), SegmentCommand64::SIZE);

        // Verify segment name
        assert_eq!(&buf[8..16], b"__SMOLVM");

        // Verify vmaddr
        let vmaddr = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        assert_eq!(vmaddr, 0x100000000);
    }
}
