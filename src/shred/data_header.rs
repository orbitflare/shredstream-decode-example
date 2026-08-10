use super::common_header::COMMON_HEADER_SIZE;

pub const DATA_HEADER_SIZE: usize = 5;
pub const DATA_HEADER_OFFSET: usize = COMMON_HEADER_SIZE;
pub const DATA_PAYLOAD_OFFSET: usize = COMMON_HEADER_SIZE + DATA_HEADER_SIZE; // 88

pub const FLAG_DATA_COMPLETE_SHRED: u8 = 0b0100_0000;
pub const FLAG_LAST_SHRED_IN_SLOT: u8 = 0b1100_0000;

#[derive(Debug, Clone)]
pub struct DataHeader {
    pub parent_offset: u16,
    pub flags: u8,
    pub size: u16,
}

pub fn is_data_complete(flags: u8) -> bool {
    flags & FLAG_DATA_COMPLETE_SHRED != 0
}

pub fn is_last_in_slot(flags: u8) -> bool {
    flags & FLAG_LAST_SHRED_IN_SLOT == FLAG_LAST_SHRED_IN_SLOT
}

pub fn parse_data_header(data: &[u8]) -> Option<DataHeader> {
    if data.len() < DATA_HEADER_OFFSET + DATA_HEADER_SIZE {
        return None;
    }

    let offset = DATA_HEADER_OFFSET;
    let parent_offset = u16::from_le_bytes(data[offset..offset + 2].try_into().ok()?);
    let flags = data[offset + 2];
    let size = u16::from_le_bytes(data[offset + 3..offset + 5].try_into().ok()?);

    Some(DataHeader {
        parent_offset,
        flags,
        size,
    })
}
