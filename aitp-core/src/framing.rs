//! Packet framing for UDP datagrams.
//!
//! Frames a complete AITP packet (header + payload) into a single UDP
//! datagram and parses incoming datagrams back into header + payload.
//!
//! Since AITP runs over UDP, each datagram is self-contained. There is
//! no stream reassembly — each datagram carries exactly one AITP packet.

use crate::header::{AitpHeader, HeaderError, HEADER_SIZE, MAX_PAYLOAD_SIZE};
use thiserror::Error;

/// Errors during packet framing.
#[derive(Debug, Error)]
pub enum FramingError {
    /// The header could not be parsed.
    #[error("header parse error: {0}")]
    HeaderError(#[from] HeaderError),

    /// Payload exceeds the maximum allowed size.
    #[error("payload too large: {size} bytes (max {MAX_PAYLOAD_SIZE})")]
    PayloadTooLarge { size: usize },

    /// Declared payload length doesn't match actual data.
    #[error("payload length mismatch: header says {declared}, actual {actual}")]
    PayloadLengthMismatch { declared: usize, actual: usize },
}

/// A fully parsed AITP packet: header + payload.
#[derive(Debug, Clone)]
pub struct AitpPacket {
    /// The parsed AITP header.
    pub header: AitpHeader,
    /// The payload bytes (may be empty for control packets).
    pub payload: Vec<u8>,
}

impl AitpPacket {
    /// Create a new packet from a header and payload.
    ///
    /// # Errors
    ///
    /// Returns [`FramingError::PayloadTooLarge`] if the payload exceeds [`MAX_PAYLOAD_SIZE`].
    pub fn new(header: AitpHeader, payload: Vec<u8>) -> Result<Self, FramingError> {
        if payload.len() > MAX_PAYLOAD_SIZE {
            return Err(FramingError::PayloadTooLarge {
                size: payload.len(),
            });
        }
        Ok(Self { header, payload })
    }

    /// Serialize the packet into a byte buffer ready for UDP transmission.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing `HEADER_SIZE + payload.len()` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.header.to_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    /// Parse a UDP datagram into an AITP packet.
    ///
    /// # Errors
    ///
    /// - [`FramingError::HeaderError`] if the header cannot be parsed.
    /// - [`FramingError::PayloadLengthMismatch`] if the payload length
    ///   declared in the header doesn't match the remaining bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<Self, FramingError> {
        let header = AitpHeader::from_bytes(buf)?;

        let payload_start = HEADER_SIZE;
        let available = buf.len().saturating_sub(payload_start);
        let declared = header.payload_len as usize;

        if available < declared {
            return Err(FramingError::PayloadLengthMismatch {
                declared,
                actual: available,
            });
        }

        let payload = buf[payload_start..payload_start + declared].to_vec();

        Ok(Self { header, payload })
    }

    /// Total wire size of this packet.
    pub fn wire_size(&self) -> usize {
        HEADER_SIZE + self.payload.len()
    }
}

// ────────────────────────── Tests ──────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{flags, IntentCode};

    fn test_header() -> AitpHeader {
        AitpHeader::new(
            flags::SYN,
            IntentCode::ModelInference,
            0x1234,
            [0xAA; 32],
            [0xBB; 32],
            180,
            11, // payload length
            1_700_000_000_000_000_000,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        )
    }

    #[test]
    fn test_packet_roundtrip() {
        let header = test_header();
        let payload = b"hello AITP!".to_vec();
        let packet = AitpPacket::new(header, payload.clone()).unwrap();

        let bytes = packet.to_bytes();
        let parsed = AitpPacket::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.header.session_id, 0x1234);
        assert_eq!(parsed.header.payload_len, 11);
    }

    #[test]
    fn test_empty_payload() {
        let mut header = test_header();
        header.payload_len = 0;
        let packet = AitpPacket::new(header, vec![]).unwrap();

        let bytes = packet.to_bytes();
        assert_eq!(bytes.len(), HEADER_SIZE);

        let parsed = AitpPacket::from_bytes(&bytes).unwrap();
        assert!(parsed.payload.is_empty());
    }

    #[test]
    fn test_payload_too_large() {
        let header = test_header();
        let payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        assert!(AitpPacket::new(header, payload).is_err());
    }

    #[test]
    fn test_payload_length_mismatch() {
        let mut header = test_header();
        header.payload_len = 100; // Claims 100 bytes
        let bytes = header.to_bytes(); // But no payload follows
        let result = AitpPacket::from_bytes(&bytes);
        assert!(matches!(
            result,
            Err(FramingError::PayloadLengthMismatch { .. })
        ));
    }

    #[test]
    fn test_wire_size() {
        let header = test_header();
        let payload = vec![0u8; 256];
        let packet = AitpPacket::new(header, payload).unwrap();
        assert_eq!(packet.wire_size(), HEADER_SIZE + 256);
    }
}
