use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BytesError {
    OutOfBounds {
        offset: usize,
        needed: usize,
        len: usize,
    },
}

impl fmt::Display for BytesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfBounds {
                offset,
                needed,
                len,
            } => {
                write!(
                    f,
                    "bytes access out of bounds: offset={} needed={} len={}",
                    offset, needed, len
                )
            }
        }
    }
}

impl std::error::Error for BytesError {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ByteBuf {
    inner: Vec<u8>,
}

impl ByteBuf {
    pub fn new() -> Self {
        Self { inner: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    pub fn from_vec(inner: Vec<u8>) -> Self {
        Self { inner }
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.inner
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn clear(&mut self) {
        self.inner.clear();
    }

    pub fn push(&mut self, byte: u8) {
        self.inner.push(byte);
    }

    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.inner.extend_from_slice(bytes);
    }

    pub fn slice(&self, offset: usize, len: usize) -> Result<&[u8], BytesError> {
        let end = offset.saturating_add(len);
        if end > self.inner.len() {
            return Err(BytesError::OutOfBounds {
                offset,
                needed: len,
                len: self.inner.len(),
            });
        }
        Ok(&self.inner[offset..end])
    }

    pub fn read_u16_le(&self, offset: usize) -> Result<u16, BytesError> {
        let bytes = self.slice(offset, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u16_be(&self, offset: usize) -> Result<u16, BytesError> {
        let bytes = self.slice(offset, 2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn read_u32_le(&self, offset: usize) -> Result<u32, BytesError> {
        let bytes = self.slice(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u32_be(&self, offset: usize) -> Result<u32, BytesError> {
        let bytes = self.slice(offset, 4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64_le(&self, offset: usize) -> Result<u64, BytesError> {
        let bytes = self.slice(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn read_u64_be(&self, offset: usize) -> Result<u64, BytesError> {
        let bytes = self.slice(offset, 8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn write_u16_le(&mut self, value: u16) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u16_be(&mut self, value: u16) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u32_le(&mut self, value: u32) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u32_be(&mut self, value: u32) {
        self.extend_from_slice(&value.to_be_bytes());
    }

    pub fn write_u64_le(&mut self, value: u64) {
        self.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64_be(&mut self, value: u64) {
        self.extend_from_slice(&value.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::{ByteBuf, BytesError};

    #[test]
    fn endian_roundtrip_and_safe_slice() {
        let mut bytes = ByteBuf::new();
        bytes.write_u16_le(0x1234);
        bytes.write_u32_be(0x0102_0304);
        bytes.write_u64_le(0x0a0b_0c0d_0e0f_1011);

        assert_eq!(bytes.read_u16_le(0).expect("u16 le"), 0x1234);
        assert_eq!(bytes.read_u32_be(2).expect("u32 be"), 0x0102_0304);
        assert_eq!(bytes.read_u64_le(6).expect("u64 le"), 0x0a0b_0c0d_0e0f_1011);

        let view = bytes.slice(2, 4).expect("slice should be in-bounds");
        assert_eq!(view, &[0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn out_of_bounds_is_rejected() {
        let bytes = ByteBuf::from_vec(vec![1, 2, 3]);
        let err = bytes.read_u32_le(0).expect_err("read should fail");
        assert!(matches!(
            err,
            BytesError::OutOfBounds {
                offset: 0,
                needed: 4,
                len: 3
            }
        ));
    }
}
