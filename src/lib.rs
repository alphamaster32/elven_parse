#![no_std]

use utils::Integer;

mod utils;

/// Elf type to store the parsed information
/// Struct members are defined according to the elf.h C header
pub struct Elf {
    /// Elf Header
    pub header: ElfHeader,
}

/// Elf Header type to store the file header information
#[derive(Debug)]
pub struct ElfHeader {
    /// Elf bitness
    pub e_class: ElfClass,

    /// Elf data encodings
    pub e_data: ElfData,

    /// Elf OS ABI
    pub e_abi: ElfOsAbi,

    /// Elf file type
    pub e_type: ElfType,

    /// Elf machine ISA
    pub e_machine: ElfMachine,

    /// Elf virtual address entry point
    pub e_entry: usize,

    /// Pointer to the start of the program header table
    pub e_phoff: usize,

    /// Pointer to the start of the section header table
    pub e_shoff: usize,

    /// Elf flags interpretation of this flag depends on the target architecture
    pub e_flags: u32,

    /// Elf header size
    pub e_ehsize: u16,

    /// Elf program header table entry size
    pub e_phentsize: u16,

    /// Elf program header table entry size
    pub e_phnum: u16,

    /// Elf section header table entry size
    pub e_shentrysize: u16,

    /// Elf Section header table entry count
    pub e_shnum: u16,

    /// Elf section header string table index that contains section names
    pub e_shstrndx: u16,
}

/// ElfClass specifies elf architecture and bitness
#[derive(Debug)]
pub enum ElfClass {
    None,
    Class32,
    Class64,
}

/// ElfData specifies elf data encodings
#[derive(Debug)]
pub enum ElfData {
    None,
    ElfData2Lsb,
    ElfData2Msb,
}

/// ElfOSAbi specifies OS ABI of the elf file
#[derive(Debug)]
pub enum ElfOsAbi {
    Sysv,
    Hpux,
    Netbsd,
    Gnu,
    Solaris,
    Aix,
    Irix,
    Freebsd,
    Tru64,
    Modesto,
    Openbsd,
    Armeabi,
    Arm,
    Standalone,
}

/// ElfType defines elf object type
#[derive(Debug)]
pub enum ElfType {
    None,
    Relocatable,
    Executable,
    SharedObject,
    CoreFile,
    OsSpecific,
    CpuSpecific,
}

/// ElfMachine Specifies machine ISA type
/// As this might get too big we will not specify all the available machine
/// types in the libc
#[derive(Debug)]
pub enum ElfMachine {
    None,
    Intel80386,
    Amd64,
    Riscv,
    Arm,
    Bpf,
    UnDefined,
}
/// Error enum to distinctify the error types
#[derive(Debug)]
pub enum Error {
    BadElf,
    OffsetCalculationFailure,
}

/// Wrapper type for the error result
type Result<T> = core::result::Result<T, Error>;

impl Default for Elf {
    fn default() -> Self {
        Self::new()
    }
}

impl Elf {
    /// Struct constructor
    pub fn new() -> Self {
        Elf {
            header: ElfHeader {
                e_class:       ElfClass::None,
                e_data:        ElfData::None,
                e_abi:         ElfOsAbi::Standalone,
                e_type:        ElfType::None,
                e_machine:     ElfMachine::None,
                e_entry:       0,
                e_phoff:       0,
                e_shoff:       0,
                e_flags:       0,
                e_ehsize:      0,
                e_phentsize:   0,
                e_phnum:       0,
                e_shentrysize: 0,
                e_shnum:       0,
                e_shstrndx:    0,
            },
        }
    }
    /// Parse the elf
    pub fn parse(mut self, elf: &[u8]) -> Result<Self> {
        // Get the elf magic number from the start of the file
        if elf.get(0x00..0x04) != Some(b"\x7FELF") {
            return Err(Error::BadElf);
        }

        // Check for the bitness of the elf file and report it back as ElfClass
        // Option type is cloned to avoid storing numbers in the .data section
        self.header.e_class = if elf.get(0x04) == Some(&1) {
            ElfClass::Class32
        } else if elf.get(0x04) == Some(&2) {
            ElfClass::Class64
        } else {
            ElfClass::None
        };

        // Check the data encoding of the elf file
        self.header.e_data = if elf.get(0x05) == Some(&1) {
            ElfData::ElfData2Lsb
        } else if elf.get(0x05) == Some(&2) {
            ElfData::ElfData2Msb
        } else {
            ElfData::None
        };

        // Check for the elf version currently this value must be 1
        if elf.get(0x06) != Some(&1) {
            return Err(Error::BadElf);
        }

        // Check for the OS ABI
        self.header.e_abi = match elf.get(0x07) {
            Some(e) => match e {
                0   => ElfOsAbi::Sysv,
                1   => ElfOsAbi::Hpux,
                2   => ElfOsAbi::Netbsd,
                3   => ElfOsAbi::Gnu,
                6   => ElfOsAbi::Solaris,
                8   => ElfOsAbi::Aix,
                9   => ElfOsAbi::Irix,
                10  => ElfOsAbi::Freebsd,
                11  => ElfOsAbi::Tru64,
                12  => ElfOsAbi::Modesto,
                64  => ElfOsAbi::Armeabi,
                97  => ElfOsAbi::Arm,
                255 => ElfOsAbi::Standalone,
                _ => ElfOsAbi::Sysv,
            },
            None => {
                return Err(Error::BadElf);
            }
        };

        // Get the abi version but discard it for future
        let _e_abi_ver = elf.get(0x08).unwrap_or(&0);

        // Discard the padding byte at 0x09 to 0x10
        let _padding = elf.get(0x09..0x10).unwrap_or(&[0u8; 7]);

        // Identify the elf type
        self.header.e_type = match elf.get(0x10..0x12) {
            Some(&[0x00, 0x00]) => ElfType::None,
            Some(&[0x01, 0x00]) => ElfType::Relocatable,
            Some(&[0x02, 0x00]) => ElfType::Executable,
            Some(&[0x03, 0x00]) => ElfType::SharedObject,
            Some(&[0x04, 0x00]) => ElfType::CoreFile,
            Some(&[0xfe, _])    => ElfType::OsSpecific,
            Some(&[0xff, _])    => ElfType::CpuSpecific,
            _ => ElfType::None,
        };

        // Get the target ISA
        self.header.e_machine = match elf.get(0x12..0x14) {
            Some(&[0x03, 0x00]) => ElfMachine::Intel80386,
            Some(&[0x3e, 0x00]) => ElfMachine::Amd64,
            Some(&[0x28, 0x00]) => ElfMachine::Arm,
            Some(&[0xf3, 0x00]) => ElfMachine::Riscv,
            Some(&[0xf7, 0x00]) => ElfMachine::Bpf,
            _ => ElfMachine::UnDefined,
        };

        // Check for the elf version for another time apparently this has more
        // options like none and current version which is 1
        if elf.get(0x14..0x18) != Some(&[0x01, 0x00, 0x00, 0x00]) {
            return Err(Error::BadElf);
        }

        //Now we need the parser position in file
        let pos: usize = 0x18;

        // Calculate the next header part ending
        let next: usize = match self.header.e_class {
            ElfClass::Class64 => 0x08 + pos,
            ElfClass::Class32 => 0x04 + pos,
            ElfClass::None    => 0x08 + pos,
        };

        // Get the elf virtual address entry point
        self.header.e_entry = usize::endian_parse(pos..next,
            elf, &self.header.e_data)?;


        // Move the position to the new header part
        let pos: usize = next;

        // Calculate the next header part ending
        let next: usize = match self.header.e_class {
            ElfClass::Class64 => 0x08 + pos,
            ElfClass::Class32 => 0x04 + pos,
            ElfClass::None    => 0x08 + pos,
        };
        
        // Get the elf program header offset
        self.header.e_phoff = usize::endian_parse(pos..next,
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = next;

        // Calculate the next header part ending
        let next: usize = match self.header.e_class {
            ElfClass::Class64 => 0x08 + pos,
            ElfClass::Class32 => 0x04 + pos,
            ElfClass::None    => 0x08 + pos,
        };

        // Get the elf section header offset
        self.header.e_shoff = usize::endian_parse(pos..next,
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = next;

        // Get the elf processor specific flags
        self.header.e_flags = u32::endian_parse(pos..(pos + 0x04),
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = pos + 0x04;
        self.header.e_ehsize = u16::endian_parse(pos..(pos + 0x02),
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = pos + 0x02;

        // Get the elf program header entry size
        self.header.e_phentsize = u16::endian_parse(pos..(pos + 0x02),
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = pos + 0x02;

        // Get the elf program header entry size
        self.header.e_phnum = u16::endian_parse(pos..(pos + 0x02),
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = pos + 0x02;

        // Get the elf section header table entry size
        self.header.e_shentrysize = u16::endian_parse(pos..(pos + 0x02),
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = pos + 0x02;

        // Get the elf section header table entry count
        self.header.e_shnum = u16::endian_parse(pos..(pos + 0x02),
            elf, &self.header.e_data)?;

        // Move the position to the new header part
        let pos: usize = pos + 0x02;

        // Get the elf section header string table
        self.header.e_shstrndx = u16::endian_parse(pos..(pos + 0x02),
            elf, &self.header.e_data)?;

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::println;
    #[test]
    fn parse_elf() {
        let file =
            std::fs::read("./tests/elf_test").expect("no file was found in the test location");
        let e = Elf::new();
        let e = e.parse(file.as_slice());
        println!("{:#x?}", e.unwrap().header);
    }
}
