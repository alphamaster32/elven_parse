use crate::{Result, Error};
use crate::section::SectionHeader;
use crate::file::{ElfData, ElfClass};
use crate::utils::Integer;

/// Symbol table stores informaion about the symbolic definitions and
/// references.
#[derive(Debug, Clone, Copy)]
pub struct SymTabIterator<'a> {
    /// The section header that points to the symtab.
    sh: Option<SectionHeader>,
    /// Number of the parsed [`SymTabEnt`] parsed. used for the iteration.
    symnum: usize,
    /// Elf class used for parsing.
    class: ElfClass,
    /// Elf endianness used for parsing.
    data: ElfData,
    /// A reference to the elf file.
    elf: &'a [u8],
}

/// Symbol tab entry. This should be parsed according to the
/// file [`file::ElfClass`](crate::file::ElfClass).
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub struct SymTabEnt {
    /// This member holds the index in the symbol string table.
    pub st_name: u32,
    /// This is the entry value.
    pub st_value: u64,
    /// Associated symbol size. Zero means no size or unknown.
    pub st_size: usize,
    /// This is the type of the binding.
    pub st_info: SymType,
    /// This specifies the symbol visibility.
    pub st_other: u8,
    /// If the symbol is defined in relation to an other section. This mostly
    /// has meaning in dynamic linking scenarios.
    /// Or if has an associated table.
    pub st_shndx: u16,
}

// FIXME: This is more nuanced than this. If this is needed we should
// fully take it into account
// https://refspecs.linuxbase.org/elf/gabi4+/ch4.symtab.html

/// Enum to identify the symbol type.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum SymType {
    #[default]
    /// Symbol type is not specified.
    None,
    /// The symbol is associated with a data object,
    /// such as a variable, an array, and so on.
    Object,
    /// This symbol is a function or an executable code.
    Func,
    /// This symbol is a section.
    Section,
    /// Symbol name gives away the source file name.
    File,
    /// Uninitialized common block.
    Common,
    /// Thread-Local storage entitiy.
    Tls,
    /// Values in this inclusive range are reserved for operating
    /// system-specific semantics.
    LoOs,
    HiOs,
    /// Values in this inclusive range are reserved for processor-specific
    /// semantics. If meanings are specified,
    /// the processor supplement explains them.
    LoProc,
    HiProc,
}

impl<'a> SymTabIterator<'a> {
    /// The default [`SymTabIterator`] constructor.
    pub fn new(
        sh: Option<SectionHeader>,
        class: ElfClass,
        data: ElfData,
        elf: &'a [u8],
    ) -> Self {
        Self {
            sh,
            symnum: 0,
            class,
            data,
            elf,
        }
    }
}

impl<'a> Iterator for SymTabIterator<'a> {
    type Item = SymTabEnt;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(symtab) = self.sh {
            // Here I hope that the compiler optimizes this :^)
            let data = &self.elf[symtab.sh_offset as usize
                ..((symtab.sh_offset + symtab.sh_size) as usize)];
            let ent_offset = self.symnum * symtab.sh_entsize as usize;
            // Really no need to limit the slice.
            let data = data.get(ent_offset..)?;
            self.symnum += 1;

            let symtab = SymTabEnt::default();
            Some(symtab.parse(data, self.class, self.data).ok()?)
        } else {
            None
        }
    }
}

impl SymTabEnt {
    /// Read an entry from the symtab. Requires an instance of strtab.
    pub fn parse(
        mut self,
        elf: &[u8],
        class: ElfClass,
        data: ElfData,
    ) -> Result<Self> {
        // This is same for each symbol table entry.
        self.st_name = u32::endian_parse(0x0..0x4, elf, &data)?;
        match class {
            ElfClass::Class32 => {
                self.st_value =
                    u32::endian_parse(0x4..0x8, elf, &data)? as u64;
                self.st_size =
                    u32::endian_parse(0x8..0xc, elf, &data)? as usize;
                self.st_info = u8::endian_parse(0xc..0xd, elf, &data)?.into();
                self.st_other = u8::endian_parse(0xd..0xe, elf, &data)?;
                self.st_shndx = u16::endian_parse(0xe..0x10, elf, &data)?;
            }
            ElfClass::Class64 => {
                self.st_info = u8::endian_parse(0x4..0x5, elf, &data)?.into();
                self.st_other = u8::endian_parse(0x5..0x6, elf, &data)?;
                self.st_shndx = u16::endian_parse(0x6..0x8, elf, &data)?;
                self.st_value = u64::endian_parse(0x8..0x10, elf, &data)?;
                self.st_size =
                    u64::endian_parse(0x10..0x18, elf, &data)? as usize;
            }
            ElfClass::None => Err(Error::UnsupportedClass)?,
        }
        Ok(self)
    }
}

impl From<u8> for SymType {
    fn from(value: u8) -> Self {
        match value {
            0 => SymType::None,
            1 => SymType::Object,
            2 => SymType::Func,
            3 => SymType::Section,
            4 => SymType::File,
            5 => SymType::Common,
            6 => SymType::Tls,
            10 => SymType::LoOs,
            11 => SymType::LoOs,
            12 => SymType::HiOs,
            13 => SymType::LoProc,
            14 => SymType::LoProc,
            15 => SymType::HiProc,
            _ => SymType::None,
        }
    }
}
