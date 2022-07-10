#![no_std]

pub struct Elf {
}

impl Elf {
    pub fn parse() {}
}

#[cfg(test)]
mod tests {
    extern crate std;
    #[test]
    fn parse_elf() {
        let mut _file = std::fs::read("./tests/elf_test");
    }
}
