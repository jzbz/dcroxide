// SPDX-License-Identifier: ISC
//! The application version constants and helpers (dcrd
//! `internal/version` at master `452c1a6c`, where the development
//! branch pins `Version = "2.2.0-pre"`).  Only the pieces the
//! handlers read at runtime are ported; the semver parsing that
//! dcrd's package `init` performs on the constant is frozen into the
//! individual components here.

/// The allowed characters for the pre-release and build metadata
/// portions of a semantic version string (dcrd `semanticAlphabet`).
const SEMANTIC_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-.";

/// The full semantic version string (dcrd `version.String()`).
pub const VERSION: &str = "2.2.0-pre";

/// The major semantic version component (dcrd `version.Major`).
pub const MAJOR: u32 = 2;

/// The minor semantic version component (dcrd `version.Minor`).
pub const MINOR: u32 = 2;

/// The patch semantic version component (dcrd `version.Patch`).
pub const PATCH: u32 = 0;

/// The pre-release portion of the version (dcrd
/// `version.PreRelease`).
pub const PRE_RELEASE: &str = "pre";

/// The build metadata portion of the version (dcrd
/// `version.BuildMetadata`).
pub const BUILD_METADATA: &str = "";

/// Strip all characters that are not valid in semantic versioning
/// pre-release and build metadata strings (dcrd
/// `version.NormalizeString`).
pub fn normalize_string(s: &str) -> String {
    s.chars()
        .filter(|c| SEMANTIC_ALPHABET.contains(*c))
        .collect()
}
