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

//! Shared error type for UnifOMR evaluation.

/// An error that can occur during UnifOMR / OMR operations.
#[derive(Debug, thiserror::Error)]
pub enum OmrError {
    #[error("Deserialization failed: {0}")]
    DeserializationError(String),

    #[error("FHE Evaluation failed: {0}")]
    EvaluationError(String),

    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}
