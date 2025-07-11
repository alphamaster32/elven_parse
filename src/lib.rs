#![no_std]

// TODO:Add methods to instantiate section types easily

mod utils;

pub mod file;
pub mod program;
pub mod section;

use file::FileHeader;
use program::ProgramIterator;
use section::{
    SectionHeader, SectionIterator, SectionType, SymTabIterator, SymTabEnt,
};

/// Elf type to store the parsed information.
/// Struct members are defined according to the elf.h C header.
pub struct Elf<'a> {
    /// Elf [`FileHeader`].
    pub file_header: FileHeader,
    /// Reference to the elf file in memory.
    pub elf: &'a [u8],
}

/// Error enum to distinctify the error types.
#[derive(Debug)]
pub enum Error {
    BadElf,
    OffsetCalculationFailure,
    UnsupportedClass,
    UnreadableSection,
    SectionNotFound,
}

/// Wrapper type for the error result
type Result<T> = core::result::Result<T, Error>;

impl<'a> core::fmt::Debug for Elf<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Display only the FileHeader not the elf file slice.
        f.debug_struct("Elf")
            .field("file_header", &self.file_header)
            .finish()
    }
}

impl<'a> Elf<'a> {
    /// The default [`Elf`] constructor.
    pub fn new(elf: &'a [u8]) -> Self {
        Elf {
            file_header: FileHeader::default(),
            elf,
        }
    }

    /// Returns the [`ProgramIterator`] to use in a loop or an iterator.
    pub fn program_iter(&self) -> program::ProgramIterator {
        ProgramIterator::new(
            self.file_header.e_phoff,
            self.file_header.e_phentsize,
            self.file_header.e_phnum,
            self.file_header.e_class,
            self.file_header.e_data,
            self.elf,
        )
    }

    /// Returns the [`SectionIterator`] to use in a loop or an iterator.
    pub fn section_iter(&self) -> section::SectionIterator {
        SectionIterator::new(
            self.file_header.e_shoff,
            self.file_header.e_shentsize,
            self.file_header.e_shnum,
            self.file_header.e_class,
            self.file_header.e_data,
            self.elf,
        )
    }

    pub fn symtab_iter(
        &self,
        symtab: SectionHeader,
    ) -> section::SymTabIterator {
        SymTabIterator::new(
            Some(symtab),
            self.file_header.e_class,
            self.file_header.e_data,
            self.elf,
        )
    }

    /// Returns the slice for the specified section.
    pub fn get_section(&self, sh: &SectionHeader) -> Result<&[u8]> {
        self.elf
            .get(sh.sh_offset as usize..((sh.sh_offset + sh.sh_size) as usize))
            .ok_or(Error::UnreadableSection)
    }

    /// This function returns the name from the shstrtab by the index. Should
    /// be passed the relavent string table.
    pub fn ndx_name(
        &self,
        ndx: usize,
        strtab: &SectionHeader,
    ) -> Option<&str> {
        let strtab = self.elf.get(
            strtab.sh_offset as usize
                ..(strtab.sh_offset + strtab.sh_size) as usize,
        )?;

        if ndx >= strtab.len() {
            return None;
        }

        // Parse the byte until null termination.
        let name_bytes = &strtab[ndx..];
        let len = name_bytes.iter().position(|&b| b == 0)?;

        core::str::from_utf8(&name_bytes[..len]).ok()
    }

    /// Helper function to find the section string table.
    pub fn find_shstrtab(&self) -> Option<SectionHeader> {
        self.section_iter().find(|&section| {
            section.sh_type == SectionType::ShtStrTab
                && self.file_header.e_shstrndx as u64 == section.sh_ndx
        })
    }

    /// This function returns the section name from the shstrtab.
    pub fn section_name(&self, sh: SectionHeader) -> Option<&str> {
        // Find the section header strtab.
        let shstrtab = self.find_shstrtab()?;
        let strtab = self.elf.get(
            shstrtab.sh_offset as usize
                ..(shstrtab.sh_offset + shstrtab.sh_size) as usize,
        )?;

        if sh.sh_name as usize >= strtab.len() {
            return None;
        }

        // Parse the byte until null termination.
        let name_bytes = &strtab[sh.sh_name as usize..];
        let len = name_bytes.iter().position(|&b| b == 0)?;
        core::str::from_utf8(&name_bytes[..len]).ok()
    }

    pub fn find_section(&self, name: &str) -> Option<SectionHeader> {
        for section in self.section_iter() {
            if let Some(section_name) = self.section_name(section) {
                if section_name == name {
                    return Some(section);
                }
            }
        }
        None
    }

    /// Return the symbol name. Should be passed relevant string table.
    pub fn sym_name(
        &self,
        sym: SymTabEnt,
        strtab: &SectionHeader,
    ) -> Option<&str> {
        self.ndx_name(sym.st_name as usize, strtab)
    }

    /// Parse the elf file and populate the struct.
    pub fn parse(mut self) -> Result<Self> {
        // Parse the elf header.
        self.file_header = self.file_header.parse(self.elf)?;

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

    #[test]
    fn read_symtab() {
        let file = std::fs::read("./tests/elf_test64")
            .expect("no file was found in the test location");
        let e = Elf::new(file.as_slice());
        let e = e.parse().unwrap();
        let strtab = e.find_section(".strtab").unwrap();
        let symtab = e.find_section(".symtab").unwrap();
        for sym in e.symtab_iter(symtab) {
            println!("{:x?}, {:?}", sym, e.sym_name(sym, &strtab));
        }
    }
}
