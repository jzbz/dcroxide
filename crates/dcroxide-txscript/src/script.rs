// SPDX-License-Identifier: ISC
//! Script analysis utilities (dcrd `script.go`), all version-0 semantics
//! with dcrd's exact consensus warnings preserved in behavior.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use crate::MAX_PUB_KEYS_PER_MULTI_SIG;
use crate::error::ScriptError;
use crate::opcode_table::*;
use crate::opcodes::disasm_opcode;
use crate::tokenizer::ScriptTokenizer;

/// Whether the opcode is a small integer: OP_0 or OP_1 through OP_16 (dcrd
/// `IsSmallInt`). Only valid for version 0 scripts.
pub fn is_small_int(op: u8) -> bool {
    op == OP_0 || (OP_1..=OP_16).contains(&op)
}

/// Whether the script is in the standard pay-to-script-hash format (dcrd
/// `IsPayToScriptHash`).
///
/// WARNING (from dcrd): always treats the script as version 0 because
/// consensus does the same.
pub fn is_pay_to_script_hash(script: &[u8]) -> bool {
    is_script_hash_script(script)
}

/// Whether the script only pushes data per the consensus definition (dcrd
/// `IsPushOnlyScript`).
///
/// WARNING (from dcrd): always treats the script as version 0 because
/// consensus does the same. Note OP_RESERVED is considered a push.
pub fn is_push_only_script(script: &[u8]) -> bool {
    const SCRIPT_VERSION: u16 = 0;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
    while tokenizer.next() {
        if tokenizer.opcode() > OP_16 {
            return false;
        }
    }
    tokenizer.err().is_none()
}

/// Whether the opcode is one of the stake tagging opcodes (dcrd
/// `isStakeOpcode`), with the treasury opcodes included when enabled.
pub(crate) fn is_stake_opcode(op: u8, is_treasury_enabled: bool) -> bool {
    if is_treasury_enabled {
        (OP_SSTX..=OP_SSTXCHANGE).contains(&op) || (OP_TADD..=OP_TGEN).contains(&op)
    } else {
        (OP_SSTX..=OP_SSTXCHANGE).contains(&op)
    }
}

/// The script hash from a standard pay-to-script-hash script, or `None`
/// (dcrd `ExtractScriptHash`). Only valid for version 0 scripts.
pub fn extract_script_hash(script: &[u8]) -> Option<&[u8]> {
    // A pay-to-script-hash script is of the form:
    //  OP_HASH160 <20-byte scripthash> OP_EQUAL
    if script.len() == 23
        && script[0] == OP_HASH160
        && script[1] == OP_DATA_20
        && script[22] == OP_EQUAL
    {
        return Some(&script[2..22]);
    }
    None
}

/// Whether the script is a standard pay-to-script-hash script (dcrd
/// `isScriptHashScript`).
pub(crate) fn is_script_hash_script(script: &[u8]) -> bool {
    extract_script_hash(script).is_some()
}

/// Whether the script is a stake-tagged pay-to-script-hash script (dcrd
/// `Engine.isStakeScriptHashScript`, parameterized on the treasury flag).
pub(crate) fn is_stake_script_hash_script(script: &[u8], is_treasury_enabled: bool) -> bool {
    script.len() == 24
        && is_stake_opcode(script[0], is_treasury_enabled)
        && script[1] == OP_HASH160
        && script[2] == OP_DATA_20
        && script[23] == OP_EQUAL
}

/// Whether the script is a regular or stake-tagged pay-to-script-hash
/// script (dcrd `Engine.isAnyKindOfScriptHash`).
pub(crate) fn is_any_kind_of_script_hash(script: &[u8], is_treasury_enabled: bool) -> bool {
    is_script_hash_script(script) || is_stake_script_hash_script(script, is_treasury_enabled)
}

/// Whether a public key script contains any stake tagging opcodes (dcrd
/// `ContainsStakeOpCodes`). Only valid for version 0 scripts.
pub fn contains_stake_op_codes(
    pk_script: &[u8],
    is_treasury_enabled: bool,
) -> Result<bool, ScriptError> {
    const SCRIPT_VERSION: u16 = 0;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, pk_script);
    while tokenizer.next() {
        if is_stake_opcode(tokenizer.opcode(), is_treasury_enabled) {
            return Ok(true);
        }
    }
    match tokenizer.into_err() {
        Some(err) => Err(err),
        None => Ok(false),
    }
}

/// Format a disassembled script for one-line printing (dcrd
/// `DisasmString`); on parse failure the disassembly up to the failure is
/// returned with `[error]` appended, along with the parse error.
///
/// Only valid for version 0 scripts.
pub fn disasm_string(script: &[u8]) -> (String, Option<ScriptError>) {
    const SCRIPT_VERSION: u16 = 0;

    let mut disbuf = String::new();
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
    if tokenizer.next() {
        disasm_opcode(&mut disbuf, tokenizer.opcode(), tokenizer.data(), true);
    }
    while tokenizer.next() {
        disbuf.push(' ');
        disasm_opcode(&mut disbuf, tokenizer.opcode(), tokenizer.data(), true);
    }
    if tokenizer.err().is_some() {
        if tokenizer.byte_index() != 0 {
            disbuf.push(' ');
        }
        disbuf.push_str("[error]");
    }
    (disbuf, tokenizer.into_err())
}

/// Whether the opcode is either not a push instruction or the push uses
/// the smallest instruction for its data (dcrd `isCanonicalPush`).
pub(crate) fn is_canonical_push(opcode: u8, data: &[u8]) -> bool {
    let data_len = data.len();
    if opcode > OP_16 {
        return true;
    }

    if opcode < OP_PUSHDATA1 && opcode > OP_0 && data_len == 1 && data[0] <= 16 {
        return false;
    }
    if opcode == OP_PUSHDATA1 && data_len < usize::from(OP_PUSHDATA1) {
        return false;
    }
    if opcode == OP_PUSHDATA2 && data_len <= 0xff {
        return false;
    }
    if opcode == OP_PUSHDATA4 && data_len <= 0xffff {
        return false;
    }
    true
}

/// The script minus any opcodes that perform a canonical push of data that
/// contains the passed data to remove (dcrd `removeOpcodeByData`).  Like
/// dcrd, which returns the input slice itself, it only allocates when a
/// push is actually removed.
///
/// Only valid for version 0 scripts.
pub(crate) fn remove_opcode_by_data<'s>(script: &'s [u8], data_to_remove: &[u8]) -> Cow<'s, [u8]> {
    // Avoid work when possible.
    if script.is_empty() || data_to_remove.is_empty() {
        return Cow::Borrowed(script);
    }

    // Parse through the script looking for a canonical data push that
    // contains the data to remove.
    const SCRIPT_VERSION: u16 = 0;
    let mut result: Option<Vec<u8>> = None;
    let mut prev_offset = 0usize;
    let mut search = Substring::new(data_to_remove);
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
    while tokenizer.next() {
        let (op, data) = (tokenizer.opcode(), tokenizer.data());
        if is_canonical_push(op, data) && search.is_in(data) {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "prev_offset is an earlier tokenizer.byte_index(), and byte_index only \
                          grows up to script.len(), so prev_offset <= byte_index and \
                          full_push_len <= script.len()"
            )]
            if result.is_none() {
                let full_push_len = tokenizer.byte_index() - prev_offset;
                let mut r = Vec::with_capacity(script.len() - full_push_len);
                r.extend_from_slice(&script[..prev_offset]);
                result = Some(r);
            }
        } else if let Some(r) = result.as_mut() {
            r.extend_from_slice(&script[prev_offset..tokenizer.byte_index()]);
        }

        prev_offset = tokenizer.byte_index();
    }
    match result {
        Some(result) => Cow::Owned(result),
        None => Cow::Borrowed(script),
    }
}

/// A search for one non-empty needle across several haystacks, standing in
/// for Go's `bytes.Contains` in [`remove_opcode_by_data`].  Go's search
/// stays near-linear on adversarial input (it falls back to Rabin-Karp
/// after repeated false starts), where a naive scan of every window costs
/// the product of the lengths, so this is Knuth-Morris-Pratt: linear in
/// the haystack after a table linear in the needle, built only once a
/// haystack longer than the needle turns up.  The answer is the same
/// either way; only the cost differs.
struct Substring<'n> {
    needle: &'n [u8],
    /// For each needle prefix `needle[..=i]`, the length of its longest
    /// proper prefix that is also its suffix; empty until first needed.
    fallback: Vec<usize>,
}

impl<'n> Substring<'n> {
    /// A search for `needle`, which must not be empty.
    fn new(needle: &'n [u8]) -> Substring<'n> {
        Substring {
            needle,
            fallback: Vec::new(),
        }
    }

    /// Whether the needle occurs in `haystack`.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "k - 1 runs only when k > 0, and k += 1 only when k < needle.len() (k <= i \
                  while building the table; the search returns once k reaches needle.len())"
    )]
    fn is_in(&mut self, haystack: &[u8]) -> bool {
        let needle = self.needle;
        if haystack.len() <= needle.len() {
            return haystack == needle;
        }
        if self.fallback.is_empty() {
            self.fallback = alloc::vec![0; needle.len()];
            let mut k = 0;
            for i in 1..needle.len() {
                while k > 0 && needle[i] != needle[k] {
                    k = self.fallback[k - 1];
                }
                if needle[i] == needle[k] {
                    k += 1;
                }
                self.fallback[i] = k;
            }
        }
        let mut k = 0;
        for &b in haystack {
            while k > 0 && b != needle[k] {
                k = self.fallback[k - 1];
            }
            if b == needle[k] {
                k += 1;
                if k == needle.len() {
                    return true;
                }
            }
        }
        false
    }
}

/// The passed small-integer opcode as an integer (dcrd `AsSmallInt`); the
/// opcode MUST be true according to [`is_small_int`].
pub fn as_small_int(op: u8) -> usize {
    if op == OP_0 {
        return 0;
    }
    usize::from(op.wrapping_sub(OP_1 - 1))
}

/// The number of signature operations in the script up to the first parse
/// failure (dcrd `countSigOpsV0`).
///
/// WARNING (from dcrd): always treats the script as version 0 because
/// consensus does the same.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "each opcode adds at most MAX_PUB_KEYS_PER_MULTI_SIG = 20, so num_sig_ops <= \
              20 * script.len(), which fits in usize for any script held in memory"
)]
fn count_sig_ops_v0(script: &[u8], precise: bool, is_treasury_enabled: bool) -> usize {
    const SCRIPT_VERSION: u16 = 0;

    let mut num_sig_ops = 0usize;
    let mut tokenizer = ScriptTokenizer::new(SCRIPT_VERSION, script);
    let mut prev_op = OP_INVALIDOPCODE;
    while tokenizer.next() {
        match tokenizer.opcode() {
            OP_TSPEND => {
                if is_treasury_enabled {
                    num_sig_ops += 1;
                }
            }

            OP_CHECKSIG | OP_CHECKSIGVERIFY | OP_CHECKSIGALT | OP_CHECKSIGALTVERIFY => {
                num_sig_ops += 1;
            }

            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                // In precise mode, small ints 1-16 immediately before the
                // opcode count exactly; everything else (including OP_0)
                // counts as the maximum, an inherited consensus rule.
                if precise && (OP_1..=OP_16).contains(&prev_op) {
                    num_sig_ops += as_small_int(prev_op);
                } else {
                    num_sig_ops += MAX_PUB_KEYS_PER_MULTI_SIG;
                }
            }

            _ => {}
        }

        prev_op = tokenizer.opcode();
    }

    num_sig_ops
}

/// A quick count of the number of signature operations in a script (dcrd
/// `GetSigOpCount`): CHECKSIG counts as 1 and CHECKMULTISIG as 20; counts
/// up to the point of any parse failure.
pub fn get_sig_op_count(script: &[u8], is_treasury_enabled: bool) -> usize {
    count_sig_ops_v0(script, false, is_treasury_enabled)
}

/// The data associated with the final opcode in the script, or `None` when
/// the script fails to parse (dcrd `finalOpcodeData`).
pub(crate) fn final_opcode_data(script_version: u16, script: &[u8]) -> Option<&[u8]> {
    // Avoid unnecessary work.
    if script.is_empty() {
        return None;
    }

    let mut data: &[u8] = &[];
    let mut tokenizer = ScriptTokenizer::new(script_version, script);
    while tokenizer.next() {
        data = tokenizer.data();
    }
    if tokenizer.err().is_some() {
        return None;
    }
    Some(data)
}

/// The number of signature operations, using the precise count for the
/// P2SH redeem script when the pair is a valid P2SH spend (dcrd
/// `GetPreciseSigOpCount`).
///
/// WARNING (from dcrd): always treats the scripts as version 0 because
/// consensus does the same.
pub fn get_precise_sig_op_count(
    script_sig: &[u8],
    script_pub_key: &[u8],
    is_treasury_enabled: bool,
) -> usize {
    const SCRIPT_VERSION: u16 = 0;

    // Treat non P2SH transactions as normal.
    if !is_script_hash_script(script_pub_key) {
        return count_sig_ops_v0(script_pub_key, true, is_treasury_enabled);
    }

    // The signature script must only push data to the stack for P2SH to be
    // a valid pair.
    if script_sig.is_empty() || !is_push_only_script(script_sig) {
        return 0;
    }

    // The P2SH script is the last item the signature script pushes to the
    // stack. Signature scripts that fail to fully parse count as 0
    // signature operations, unlike public key and redeem scripts.
    let redeem_script = final_opcode_data(SCRIPT_VERSION, script_sig);
    match redeem_script {
        None | Some([]) => 0,
        Some(redeem) => count_sig_ops_v0(redeem, true, is_treasury_enabled),
    }
}

/// Returns an error if the script fails to parse (dcrd
/// `checkScriptParses`).
pub(crate) fn check_script_parses(script_version: u16, script: &[u8]) -> Result<(), ScriptError> {
    let mut tokenizer = ScriptTokenizer::new(script_version, script);
    while tokenizer.next() {
        // Nothing to do.
    }
    match tokenizer.into_err() {
        Some(err) => Err(err),
        None => Ok(()),
    }
}

/// Whether the public key script is unspendable / guaranteed to fail at
/// execution (dcrd `IsUnspendable`); in Decred all zero-value outputs are
/// unspendable. Only valid for version 0 scripts.
pub fn is_unspendable(amount: i64, pk_script: &[u8]) -> bool {
    // Starts with OP_RETURN or is larger than the max allowed script size.
    if amount == 0
        || pk_script.len() > crate::MAX_SCRIPT_SIZE
        || (!pk_script.is_empty() && pk_script[0] == OP_RETURN)
    {
        return true;
    }

    // Unspendable if it is guaranteed to fail at execution.
    const SCRIPT_VERSION: u16 = 0;
    check_script_parses(SCRIPT_VERSION, pk_script).is_err()
}

/// Generate a block reference script for the given block hash and height
/// for use in stake vote transactions (dcrd `GenerateSSGenBlockRef`).
pub fn generate_ssgen_block_ref(
    block_hash: dcroxide_chainhash::Hash,
    height: u32,
) -> Result<Vec<u8>, crate::builder::NotCanonicalError> {
    let mut br_bytes = [0u8; 36];
    br_bytes[0..32].copy_from_slice(&block_hash.0);
    br_bytes[32..36].copy_from_slice(&height.to_le_bytes());

    crate::builder::ScriptBuilder::new()
        .add_op(OP_RETURN)
        .add_data(&br_bytes)
        .script()
}

/// Generate a vote script for the given vote bits for use in stake vote
/// transactions (dcrd `GenerateSSGenVotes`).
pub fn generate_ssgen_votes(votebits: u16) -> Result<Vec<u8>, crate::builder::NotCanonicalError> {
    crate::builder::ScriptBuilder::new()
        .add_op(OP_RETURN)
        .add_data(&votebits.to_le_bytes())
        .script()
}

#[cfg(test)]
mod tests {
    use alloc::borrow::Cow;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::{Substring, remove_opcode_by_data};

    /// The KMP search answers exactly what the naive scan of every window
    /// does, including on the periodic near-misses that make the naive
    /// scan quadratic, and for haystacks shorter than, equal to and
    /// longer than the needle.
    #[test]
    fn substring_search_matches_the_naive_scan() {
        let naive = |haystack: &[u8], needle: &[u8]| {
            haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle)
        };
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize
        };
        for _ in 0..4000 {
            // A two-letter alphabet makes partial matches, and so the
            // fallback table, do real work.
            let needle: Vec<u8> = (0..1 + next() % 9).map(|_| (next() % 2) as u8).collect();
            let haystack: Vec<u8> = (0..next() % 40).map(|_| (next() % 2) as u8).collect();
            let mut search = Substring::new(&needle);
            assert_eq!(
                search.is_in(&haystack),
                naive(&haystack, &needle),
                "needle {needle:?} haystack {haystack:?}"
            );
            // The table built for one haystack serves the next.
            let other: Vec<u8> = (0..next() % 40).map(|_| (next() % 2) as u8).collect();
            assert_eq!(search.is_in(&other), naive(&other, &needle));
        }

        // The quadratic case for a naive scan: zeros against zeros ending
        // in a one.
        let mut needle = vec![0u8; 1024];
        needle[1023] = 1;
        let mut search = Substring::new(&needle);
        let mut haystack = vec![0u8; 2048];
        assert!(!search.is_in(&haystack));
        haystack[2047] = 1;
        assert!(search.is_in(&haystack));
    }

    /// Like dcrd, which returns its input slice, nothing is copied unless
    /// a push is removed; a matching canonical push is dropped whole and a
    /// non-canonical one is kept.
    #[test]
    fn remove_opcode_by_data_borrows_unless_it_removes() {
        // OP_DATA_3 01 02 03, OP_DUP.
        let script = [0x03, 0x01, 0x02, 0x03, 0x76];
        assert!(matches!(
            remove_opcode_by_data(&script, &[0x09]),
            Cow::Borrowed(s) if s == script
        ));
        assert!(matches!(
            remove_opcode_by_data(&script, &[]),
            Cow::Borrowed(s) if s == script
        ));
        assert!(matches!(
            remove_opcode_by_data(&script, &[0x02, 0x03]),
            Cow::Owned(s) if s == [0x76]
        ));

        // OP_PUSHDATA1 of three bytes is not canonical, so it stays.
        let non_canonical = [0x4c, 0x03, 0x01, 0x02, 0x03, 0x76];
        assert!(matches!(
            remove_opcode_by_data(&non_canonical, &[0x02]),
            Cow::Borrowed(s) if s == non_canonical
        ));
    }
}
