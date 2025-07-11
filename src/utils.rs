use crate::file::ElfData;
use crate::Error;

pub trait Integer: Sized {
    fn endian_parse(
        range: core::ops::Range<usize>,
        bytes: &[u8],
        e_data: &ElfData,
    ) -> crate::Result<Self>;
}

macro_rules! impl_integer {
    ($t:ty) => {
        impl Integer for $t {
            fn endian_parse(
                range: core::ops::Range<usize>,
                bytes: &[u8],
                e_data: &ElfData,
            ) -> crate::Result<Self> {
                let arr: [u8; core::mem::size_of::<$t>()] = bytes
                    .get(range)
                    .ok_or(Error::OffsetCalculationFailure)?
                    .try_into()
                    .map_err(|_| Error::OffsetCalculationFailure)?;

                Ok(match e_data {
                    ElfData::ElfData2Lsb | ElfData::None => {
                        <$t>::from_le_bytes(arr)
                    }
                    ElfData::ElfData2Msb => <$t>::from_be_bytes(arr),
                })
            }
        }
    };
}

impl_integer!(u8);
impl_integer!(u16);
impl_integer!(u32);
impl_integer!(u64);
impl_integer!(usize);
