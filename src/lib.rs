#![no_std]

// TODO:Add methods to instantiate section types easily

mod utils;

pub mod file;
pub mod program;
pub mod section;

use file::FileHeader;
use program::ProgramIterator;
use section::{SectionHeader, SectionIterator, SectionType};

/// Elf type to store the parsed information
/// Struct members are defined according to the elf.h C header
pub struct Elf<'a> {
    /// Elf file header
    pub file_header: FileHeader,
    /// Reference to the elf file in memory
    pub elf: &'a [u8],
    /// 'SectionType::ShtStrTab' reference so we only find it once
    pub shtstrtab: Option<SectionHeader>,
}

/// Error enum to distinctify the error types
#[derive(Debug)]
pub enum Error {
    BadElf,
    OffsetCalculationFailure,
    UnsupportedClass,
    UnreadableSection,
}

/// Wrapper type for the error result
type Result<T> = core::result::Result<T, Error>;

impl<'a> core::fmt::Debug for Elf<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Display only the FileHeader not the elf file slice
        f.debug_struct("Elf")
            .field("file_header", &self.file_header)
            .finish()
    }
}

impl<'a> Elf<'a> {
    /// The default `Elf` constructor
    pub fn new(elf: &'a [u8]) -> Self {
        Elf {
            file_header: FileHeader::new(),
            elf,
            shtstrtab: None,
        }
    }

    /// Returns the `ProgramIterator` to use in a loop or an iterator
    pub fn program_iter(&'a self) -> program::ProgramIterator {
        ProgramIterator::new(
            self.file_header.e_phoff,
            self.file_header.e_phentsize,
            self.file_header.e_phnum,
            self.file_header.e_class,
            self.file_header.e_data,
            self.elf,
        )
    }

    /// Returns the `SectionIterator` to use in a loop or an iterator
    pub fn section_iter(&'a self) -> section::SectionIterator {
        SectionIterator::new(
            self.file_header.e_shoff,
            self.file_header.e_shentsize,
            self.file_header.e_shnum,
            self.file_header.e_class,
            self.file_header.e_data,
            self.elf,
        )
    }

    /// Returns the slice for the specified section
    pub fn get_section(
        &'a self,
        sh: SectionHeader,
    ) -> Result<&'a [u8]> {
        Ok(self
            .elf
            .get(sh.sh_offset..(sh.sh_offset + sh.sh_size))
            .ok_or(Error::UnreadableSection)?)
    }

    /// This function returns the section name from the shstrtab
    pub fn section_name(&'a self, sh: SectionHeader) -> Option<&str> {
        if let Some(shtstrtab) = self.shtstrtab {
            // FIXME: this should use the `get_section` function
            if let Some(strtab) = self.elf.get(
                shtstrtab.sh_offset..(shtstrtab.sh_offset + shtstrtab.sh_size),
            ) {
                let mut ndx: usize = 0;
                let it = strtab.iter().skip(sh.sh_name as usize);
                // Parse the byte until null termination
                for &byte in it {
                    if byte != b'\0' {
                        ndx += 1;
                    } else {
                        break;
                    }
                }
                // Parse the string from byte slice
                if let Some(name) = core::str::from_utf8(
                    strtab
                        .get(
                            (sh.sh_name as usize)
                                ..((sh.sh_name as usize) + ndx),
                        )
                        .unwrap(),
                )
                .ok()
                {
                    Some(name)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Parse the elf file and populate the struct
    pub fn parse(mut self) -> Result<Self> {
        // Parse the elf header
        self.file_header = self.file_header.parse(self.elf)?;

        let mut sht: SectionHeader = SectionHeader::new();
        if self.shtstrtab == None {
            for section in self.section_iter() {
                if section.sh_type == SectionType::ShtStrTab
                    && self.file_header.e_shstrndx as usize == section.sh_ndx
                {
                    sht = section.clone();
                    break;
                }
            }
        }
        self.shtstrtab = Some(sht);

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::println;

    #[test]
    fn parse_elf32() {
        let file = std::fs::read("./tests/elf_test32")
            .expect("no file was found in the test location");
        let e = Elf::new(file.as_slice());
        let e = e.parse().unwrap();
        for program in e.program_iter() {
            println!("{:#x?}", program);
        }
        for section in e.section_iter() {
            println!("{:#x?}", section);
        }
        println!("{:#x?}", e);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn parse_elf64() {
        let file = std::fs::read("./tests/elf_test64")
            .expect("no file was found in the test location");
        let e = Elf::new(file.as_slice());
        let e = e.parse().unwrap();
        for program in e.program_iter() {
            println!("{:#x?}", program);
        }
        for section in e.section_iter() {
            println!("{:#x?}", section);
        }
        println!("{:#x?}", e);
    }
}
