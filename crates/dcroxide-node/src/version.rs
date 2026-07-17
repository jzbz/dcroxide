// SPDX-License-Identifier: ISC
//! The application version machinery (dcrd `internal/version`):
//! semantic version parsing with dcrd's exact error texts, the
//! normalization helper, and the pinned release version.  dcrd's
//! `vcsCommitID` fallback reads the Go build info when the build
//! metadata is empty; the release version carries explicit metadata,
//! so that path never runs at the parity tag and is not ported.

use std::sync::OnceLock;

use crate::gostd::go_quote;

/// The allowed characters for the pre-release and build metadata
/// portions of a semantic version string (dcrd `semanticAlphabet`).
const SEMANTIC_ALPHABET: &str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-.";

/// The application version per the semantic versioning 2.0.0 spec
/// (dcrd `Version` at release-v2.1.5).
pub const VERSION: &str = "2.1.5+release.local";

/// The parsed semantic version components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    /// The major version.
    pub major: u32,
    /// The minor version.
    pub minor: u32,
    /// The patch version.
    pub patch: u32,
    /// The pre-release portion.
    pub pre_release: String,
    /// The build metadata portion.
    pub build_metadata: String,
}

/// The parsed application version components (dcrd's package
/// `init`).
pub fn version_components() -> &'static SemVer {
    static COMPONENTS: OnceLock<SemVer> = OnceLock::new();
    COMPONENTS.get_or_init(|| parse_sem_ver(VERSION).expect("release version parses"))
}

/// The application version as a properly formed semantic version
/// string (dcrd `String`).
pub fn version_string() -> &'static str {
    VERSION
}

/// The strictly numeric `major.minor.patch` version advertised in the
/// peer-to-peer user agent and the RPC server's version reporting
/// (dcrd server.go's `userAgentVersion`, which deliberately excludes
/// the pre-release and build metadata portions).
pub fn user_agent_version() -> String {
    let c = version_components();
    format!("{}.{}.{}", c.major, c.minor, c.patch)
}

/// Whether an identifier is numeric with no leading zeros (the
/// `0|[1-9]\d*` alternates of dcrd's `semverRE`).
fn numeric_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()) && (id == "0" || !id.starts_with('0'))
}

/// Whether a pre-release identifier matches
/// `0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*`: a numeric identifier with
/// no leading zeros, or any alphanumeric-and-hyphen run containing
/// at least one non-digit.
fn pre_release_identifier(id: &str) -> bool {
    if id.is_empty() || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return false;
    }
    if id.bytes().all(|b| b.is_ascii_digit()) {
        return id == "0" || !id.starts_with('0');
    }
    true
}

/// Whether a build metadata identifier matches `[0-9a-zA-Z-]+`.
fn build_identifier(id: &str) -> bool {
    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// Split a version string the way dcrd's `semverRE` matches it,
/// returning the core, pre-release, and build portions or `None`
/// when the string does not conform.
fn split_sem_ver(s: &str) -> Option<(&str, &str, &str)> {
    // The build metadata follows the first '+'; its identifiers
    // exclude '+', so a second one fails validation below.
    let (rest, build, has_build) = match s.split_once('+') {
        Some((rest, build)) => (rest, build, true),
        None => (s, "", false),
    };
    // The pre-release follows the first '-' before the build; its
    // identifiers may contain further hyphens.
    let (core, pre, has_pre) = match rest.split_once('-') {
        Some((core, pre)) => (core, pre, true),
        None => (rest, "", false),
    };

    let core_parts: Vec<&str> = core.split('.').collect();
    if core_parts.len() != 3 || !core_parts.iter().all(|p| numeric_identifier(p)) {
        return None;
    }
    // An explicit but empty portion fails through its single empty
    // identifier.
    if has_pre && !pre.split('.').all(pre_release_identifier) {
        return None;
    }
    if has_build && !build.split('.').all(build_identifier) {
        return None;
    }
    Some((core, pre, build))
}

/// Convert a numeric component like dcrd `parseUint32`, with the Go
/// `strconv.ParseUint` error text on overflow.
fn parse_uint32(s: &str, field_name: &str) -> Result<u32, String> {
    // The digits are already validated; only the range can fail.
    s.parse::<u32>().map_err(|_| {
        format!(
            "malformed semver {field_name}: strconv.ParseUint: parsing {}: value out of range",
            go_quote(s)
        )
    })
}

/// Return an error when the string contains characters outside the
/// alphabet (dcrd `checkSemString`); unreachable after the
/// structural checks but ported for fidelity.
fn check_sem_string(s: &str, alphabet: &str, field_name: &str) -> Result<(), String> {
    for r in s.chars() {
        if !alphabet.contains(r) {
            return Err(format!("malformed semver {field_name}: '{r}' invalid"));
        }
    }
    Ok(())
}

/// Parse the semver components from the provided string (dcrd
/// `parseSemVer`), with dcrd's exact error texts.
pub fn parse_sem_ver(s: &str) -> Result<SemVer, String> {
    let Some((core, pre, build)) = split_sem_ver(s) else {
        return Err(format!(
            "malformed version string {}: does not conform to semver specification",
            go_quote(s)
        ));
    };
    let mut parts = core.split('.');
    let major = parse_uint32(parts.next().expect("three parts"), "major")?;
    let minor = parse_uint32(parts.next().expect("three parts"), "minor")?;
    let patch = parse_uint32(parts.next().expect("three parts"), "patch")?;
    check_sem_string(pre, SEMANTIC_ALPHABET, "pre-release")?;
    check_sem_string(build, SEMANTIC_ALPHABET, "buildmetadata")?;
    Ok(SemVer {
        major,
        minor,
        patch,
        pre_release: pre.to_string(),
        build_metadata: build.to_string(),
    })
}

/// Strip all characters which are not valid in semantic versioning
/// pre-release and build metadata strings (dcrd `NormalizeString`).
pub fn normalize_string(s: &str) -> String {
    s.chars()
        .filter(|r| SEMANTIC_ALPHABET.contains(*r))
        .collect()
}
