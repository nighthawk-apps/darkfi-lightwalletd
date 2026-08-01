//! OMR transaction envelope parsing (matches mobile wallet wire format).
//!
//! Tag `O2` + u16 memo length + u32 clue length (UnifOMR clues can be multi-KB).

pub const OMR_ENVELOPE_TAG: &[u8; 2] = b"O2";

pub struct OmrEnvelope<'a> {
    pub omr_memo: &'a [u8],
    pub fhe_clue: &'a [u8],
    pub raw_tx: &'a [u8],
}

pub fn parse_envelope(data: &[u8]) -> Option<OmrEnvelope<'_>> {
    if data.len() < 5 {
        return None;
    }
    if data[0] == b'O' && data[1] == b'2' {
        return parse_o2(data);
    }
    None
}

fn parse_o2(data: &[u8]) -> Option<OmrEnvelope<'_>> {
    let memo_len = u16::from_le_bytes([data[2], data[3]]) as usize;
    let memo_end = 4 + memo_len;
    if data.len() < memo_end + 4 {
        return None;
    }
    let clue_len = u32::from_le_bytes(data[memo_end..memo_end + 4].try_into().ok()?) as usize;
    if clue_len > 65_536 {
        return None;
    }
    let clue_start = memo_end + 4;
    let clue_end = clue_start.checked_add(clue_len)?;
    if clue_end > data.len() {
        return None;
    }
    Some(OmrEnvelope {
        omr_memo: &data[4..memo_end],
        fhe_clue: &data[clue_start..clue_end],
        raw_tx: &data[clue_end..],
    })
}

pub fn strip_envelope(data: &[u8]) -> &[u8] {
    parse_envelope(data).map(|e| e.raw_tx).unwrap_or(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_envelope_large_clue() {
        let memo = [0x4Fu8, 0x05];
        let clue = vec![0xABu8; 1000];
        let mut data = Vec::new();
        data.extend_from_slice(OMR_ENVELOPE_TAG);
        data.extend_from_slice(&(memo.len() as u16).to_le_bytes());
        data.extend_from_slice(&memo);
        data.extend_from_slice(&(clue.len() as u32).to_le_bytes());
        data.extend_from_slice(&clue);
        data.extend_from_slice(b"rawtx");
        let env = parse_envelope(&data).unwrap();
        assert_eq!(env.fhe_clue.len(), 1000);
        assert_eq!(env.raw_tx, b"rawtx");
    }

    #[test]
    fn rejects_invalid_om_tag() {
        let mut data = vec![
            b'O', b'M', 0x01, 0x00, 0x4F, 0x08, 0x42, 0, 0, 0, 0, 0, 0, 0,
        ];
        data.extend_from_slice(b"tx");
        assert!(parse_envelope(&data).is_none());
        assert_eq!(strip_envelope(&data), data.as_slice());
    }
}
