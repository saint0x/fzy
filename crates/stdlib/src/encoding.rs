use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt;

const BASE64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

#[derive(Debug)]
pub enum EncodingError {
    Json(serde_json::Error),
    InvalidBase64Length,
    InvalidBase64Byte(char),
    InvalidHexLength,
    InvalidHexByte(char),
}

impl fmt::Display for EncodingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(err) => write!(f, "json error: {err}"),
            Self::InvalidBase64Length => write!(f, "invalid base64 length"),
            Self::InvalidBase64Byte(ch) => write!(f, "invalid base64 character: {ch}"),
            Self::InvalidHexLength => write!(f, "invalid hex length"),
            Self::InvalidHexByte(ch) => write!(f, "invalid hex character: {ch}"),
        }
    }
}

impl std::error::Error for EncodingError {}

pub fn json_encode<T: Serialize>(value: &T) -> Result<String, EncodingError> {
    serde_json::to_string(value).map_err(EncodingError::Json)
}

pub fn json_decode<T: DeserializeOwned>(text: &str) -> Result<T, EncodingError> {
    serde_json::from_str(text).map_err(EncodingError::Json)
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(text: &str) -> Result<Vec<u8>, EncodingError> {
    if text.len() % 2 != 0 {
        return Err(EncodingError::InvalidHexLength);
    }

    let mut out = Vec::with_capacity(text.len() / 2);
    let chars: Vec<char> = text.chars().collect();
    let mut idx = 0usize;
    while idx < chars.len() {
        let hi = decode_hex_nibble(chars[idx])?;
        let lo = decode_hex_nibble(chars[idx + 1])?;
        out.push((hi << 4) | lo);
        idx += 2;
    }
    Ok(out)
}

pub fn base64_encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }

    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };

        let i0 = (b0 >> 2) as usize;
        let i1 = (((b0 & 0x03) << 4) | (b1 >> 4)) as usize;
        let i2 = (((b1 & 0x0f) << 2) | (b2 >> 6)) as usize;
        let i3 = (b2 & 0x3f) as usize;

        out.push(BASE64_TABLE[i0] as char);
        out.push(BASE64_TABLE[i1] as char);
        if chunk.len() > 1 {
            out.push(BASE64_TABLE[i2] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(BASE64_TABLE[i3] as char);
        } else {
            out.push('=');
        }
    }
    out
}

pub fn base64_decode(text: &str) -> Result<Vec<u8>, EncodingError> {
    if text.is_empty() {
        return Ok(Vec::new());
    }
    if text.len() % 4 != 0 {
        return Err(EncodingError::InvalidBase64Length);
    }

    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity((chars.len() / 4) * 3);

    let mut idx = 0usize;
    while idx < chars.len() {
        let c0 = chars[idx];
        let c1 = chars[idx + 1];
        let c2 = chars[idx + 2];
        let c3 = chars[idx + 3];

        let v0 = decode_base64(c0)?;
        let v1 = decode_base64(c1)?;
        let v2 = if c2 == '=' { 0 } else { decode_base64(c2)? };
        let v3 = if c3 == '=' { 0 } else { decode_base64(c3)? };

        out.push((v0 << 2) | (v1 >> 4));
        if c2 != '=' {
            out.push(((v1 & 0x0f) << 4) | (v2 >> 2));
        }
        if c3 != '=' {
            out.push(((v2 & 0x03) << 6) | v3);
        }
        idx += 4;
    }

    Ok(out)
}

fn decode_hex_nibble(ch: char) -> Result<u8, EncodingError> {
    match ch {
        '0'..='9' => Ok((ch as u8) - b'0'),
        'a'..='f' => Ok((ch as u8) - b'a' + 10),
        'A'..='F' => Ok((ch as u8) - b'A' + 10),
        _ => Err(EncodingError::InvalidHexByte(ch)),
    }
}

fn decode_base64(ch: char) -> Result<u8, EncodingError> {
    match ch {
        'A'..='Z' => Ok((ch as u8) - b'A'),
        'a'..='z' => Ok((ch as u8) - b'a' + 26),
        '0'..='9' => Ok((ch as u8) - b'0' + 52),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(EncodingError::InvalidBase64Byte(ch)),
    }
}

#[cfg(test)]
mod tests {
    use super::{base64_decode, base64_encode, hex_decode, hex_encode, json_decode, json_encode};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Payload {
        name: String,
        count: i32,
    }

    #[test]
    fn json_roundtrip() {
        let payload = Payload {
            name: "ops".to_string(),
            count: 7,
        };
        let encoded = json_encode(&payload).expect("encode");
        let decoded: Payload = json_decode(&encoded).expect("decode");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = b"fozzy";
        let hex = hex_encode(bytes);
        assert_eq!(hex, "666f7a7a79");
        let decoded = hex_decode(&hex).expect("decode");
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn base64_roundtrip() {
        let bytes = b"interop";
        let b64 = base64_encode(bytes);
        assert_eq!(b64, "aW50ZXJvcA==");
        let decoded = base64_decode(&b64).expect("decode");
        assert_eq!(decoded, bytes);
    }
}
