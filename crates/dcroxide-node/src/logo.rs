// SPDX-License-Identifier: ISC
//! The dcroxide startup banner.  This is a dcroxide-specific
//! cosmetic addition — dcrd prints only a version log line at
//! startup — and it goes to standard output before the logging
//! subsystem takes over, so it never lands in log files.

/// The DCROXIDE block-letter logo, 60 columns wide so it fits an
/// 80-column terminal.
pub const LOGO: &str = "\
██████╗  ██████╗██████╗  ██████╗ ██╗  ██╗██╗██████╗ ███████╗
██╔══██╗██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝██║██╔══██╗██╔════╝
██║  ██║██║     ██████╔╝██║   ██║ ╚███╔╝ ██║██║  ██║█████╗
██║  ██║██║     ██╔══██╗██║   ██║ ██╔██╗ ██║██║  ██║██╔══╝
██████╔╝╚██████╗██║  ██║╚██████╔╝██╔╝ ██╗██║██████╔╝███████╗
╚═════╝  ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚═════╝ ╚══════╝";

/// The logo width in display columns.
const LOGO_WIDTH: usize = 60;

/// The startup banner: the logo with the tagline and version
/// centered beneath it.  The daemon shell prints this once when the
/// node starts.
pub fn startup_banner(version: &str) -> String {
    let tagline = format!("dcrd, oxidized — v{version}");
    let columns = tagline.chars().count();
    let pad = LOGO_WIDTH.saturating_sub(columns) / 2;
    format!("{LOGO}\n{:pad$}{tagline}\n", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_is_terminal_friendly() {
        let banner = startup_banner(crate::version::version_string());
        for line in banner.lines() {
            // Display width: every glyph in the logo occupies one
            // column, so the char count is the column count.
            assert!(line.chars().count() <= 80, "line too wide: {line}");
        }
        assert!(banner.contains("2.1.5+release.local"));
        assert_eq!(banner.lines().count(), 7);
    }
}
