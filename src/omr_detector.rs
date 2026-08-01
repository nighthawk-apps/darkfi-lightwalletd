/* This file is part of Nighthawk Apps (https://nighthawkapps.com)
 *
 * Copyright (C) 2026 Nighthawk Apps
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

//! Note containers for the UnifOMR / cache path.
//!
//! Detection lives in [`crate::unifomr`] and is exposed over gRPC via
//! `GetUnifOmrDigest` + `FetchPirBatch`. This module only holds
//! [`NoteForDetection`] shared by the cache and UnifOMR evaluators.

/// A note prepared for UnifOMR detection.
///
/// Contains both the encrypted note (for compact-block reassembly / trial
/// decrypt) and an optional OMR clue (preferred when present for UnifOMR).
#[derive(Debug, Clone)]
pub struct NoteForDetection {
    /// The serialized AeadEncryptedNote: VarInt(ciphertext_len) + ciphertext + ephem_public(32 bytes)
    pub encrypted_note: Vec<u8>,
    /// Optional UnifOMR clue from the sender. When non-empty, detection
    /// uses this clue rather than the encrypted note body.
    pub omr_clue: Vec<u8>,
}
