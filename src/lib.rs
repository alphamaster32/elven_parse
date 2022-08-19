#![no_std]

mod utils;

pub mod file;
pub mod program;

use file::FileHeader;
use program::ProgramIterator;

/// Elf type to store the parsed information
/// Struct members are defined according to the elf.h C header
#[derive(Debug)]
pub struct Elf {
    /// Elf file header
    pub file_header: FileHeader,
}

/// Iterator for the program header

/// Error enum to distinctify the error types
#[derive(Debug)]
pub enum Error {
    BadElf,
    OffsetCalculationFailure,
    UnsupportedClass,
}

/// Wrapper type for the error result
type Result<T> = core::result::Result<T, Error>;

impl Default for Elf {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Elf {
    /// The default `Elf` constructor
    pub fn new() -> Self {
        Elf {
            file_header: FileHeader::new(),
        }
    }

    /// Returns the `ProgramIterator` to use in a loop or an iterator
    pub fn program_iter(&'a self, elf: &'a[u8]) -> program::ProgramIterator {
        ProgramIterator::new(self.file_header.e_phoff, 
            self.file_header.e_phentsize, self.file_header.e_phnum, 
            self.file_header.e_class, self.file_header.e_data, elf)
    }

    /// Parse the elf file and populate the struct
    pub fn parse(mut self, elf: &[u8]) -> Result<Self> {
        // Parse the elf header
        self.file_header = self.file_header.parse(elf)?;

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
        let file =
            std::fs::read("./tests/elf_test32")
            .expect("no file was found in the test location");
        let e = Elf::new();
        let e = e.parse(file.as_slice()).unwrap();
        for program in e.program_iter(file.as_slice()) {
            println!("{:#x?}", program);
        }
        println!("{:#x?}", e);
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn parse_elf64() {
        let file =
            std::fs::read("./tests/elf_test64")
            .expect("no file was found in the test location");
        let e = Elf::new();
        let e = e.parse(file.as_slice()).unwrap();
        for program in e.program_iter(file.as_slice()) {
            println!("{:#x?}", program);
        }
        println!("{:#x?}", e);
    }
}
