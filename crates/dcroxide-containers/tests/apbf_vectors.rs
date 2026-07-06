// SPDX-License-Identifier: ISC
//! Replay of dcrd's age-partitioned bloom filter behavior generated
//! inside dcrd's container/apbf package (`data/apbf_vectors.txt`):
//! the 128-bit siphash word mapping, the false positive rate
//! recursion bit for bit, the construction metadata across dcrd's
//! own parameter tables, and scripted add/probe/age/reset sessions
//! with injected hash keys comparing the packed ring buffer byte for
//! byte and the membership verdicts — false positives included —
//! bit for bit.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use dcroxide_containers::apbf::{Filter, calc_fp_rate, new_filter, new_filter_kl, siphash128};
use dcroxide_testutil::unhex;

fn raw_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn apbf_vectors() {
    let data = include_str!("data/apbf_vectors.txt");
    let mut lines = data.lines().peekable();

    let mut filter: Option<Filter> = None;
    let mut counts = [0usize; 6];

    let check_meta = |filter: &Filter, want: &str| {
        let (items_per_generation, bits_per_slice) = filter.internal_params();
        let (_, _, data) = filter.internal_state();
        let got = format!(
            "meta {} {:016x} {} {} {} {} {} {}",
            filter.capacity(),
            filter.fp_rate().to_bits(),
            filter.size(),
            filter.k(),
            filter.l(),
            items_per_generation,
            bits_per_slice,
            data.len()
        );
        assert_eq!(got, want, "filter metadata");
    };
    let check_state = |filter: &Filter, want: &str| {
        let (base_index, items_in_cur_generation, data) = filter.internal_state();
        let got = format!(
            "state {} {} {}",
            base_index,
            items_in_cur_generation,
            raw_hex(data)
        );
        assert_eq!(got, want, "filter state");
    };
    let be_data = |i: u32| i.to_be_bytes();

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "sip128" => {
                let k0: u64 = f[1].parse().expect("k0");
                let k1: u64 = f[2].parse().expect("k1");
                let data = if f[3] == "-" { Vec::new() } else { unhex(f[3]) };
                let want_h1: u64 = f[4].parse().expect("h1");
                let want_h2: u64 = f[5].parse().expect("h2");
                assert_eq!(siphash128(k0, k1, &data), (want_h1, want_h2), "{line}");
                counts[0] += 1;
            }
            "fprate" => {
                let k: u8 = f[1].parse().expect("k");
                let l: u8 = f[2].parse().expect("l");
                let want = u64::from_str_radix(f[3], 16).expect("bits");
                assert_eq!(calc_fp_rate(k, l).to_bits(), want, "{line}");
                counts[1] += 1;
            }
            "newkl" => {
                let min_capacity: u32 = f[1].parse().expect("capacity");
                let k: u8 = f[2].parse().expect("k");
                let l: u8 = f[3].parse().expect("l");
                let mut new = new_filter_kl(min_capacity, k, l);
                new.set_keys(f[4].parse().expect("key0"), f[5].parse().expect("key1"));
                check_meta(&new, lines.next().expect("meta line"));
                filter = Some(new);
                counts[2] += 1;
            }
            "new" => {
                let min_capacity: u32 = f[1].parse().expect("capacity");
                let fp_rate = f64::from_bits(u64::from_str_radix(f[2], 16).expect("bits"));
                let mut new = new_filter(min_capacity, fp_rate);
                new.set_keys(f[3].parse().expect("key0"), f[4].parse().expect("key1"));
                check_meta(&new, lines.next().expect("meta line"));
                filter = Some(new);
                counts[2] += 1;
            }
            "addseq" => {
                let filter = filter.as_mut().expect("filter");
                let start: u32 = f[1].parse().expect("start");
                let count: u32 = f[2].parse().expect("count");
                for i in start..start + count {
                    filter.add(&be_data(i));
                }
                check_state(filter, lines.next().expect("state line"));
                counts[3] += 1;
            }
            "probeseq" => {
                let filter = filter.as_ref().expect("filter");
                let start: u32 = f[1].parse().expect("start");
                let count: u32 = f[2].parse().expect("count");
                let mut bitmap = vec![0u8; (count as usize).div_ceil(8)];
                for i in 0..count {
                    if filter.contains(&be_data(start + i)) {
                        bitmap[(i >> 3) as usize] |= 1 << (i & 7);
                    }
                }
                assert_eq!(raw_hex(&bitmap), f[3], "{line}");
                counts[4] += 1;
            }
            "nextgen" => {
                let filter = filter.as_mut().expect("filter");
                filter.next_generation();
                check_state(filter, lines.next().expect("state line"));
            }
            "reset" => {
                let filter = filter.as_mut().expect("filter");
                filter.reset();
                let want_keys = lines.next().expect("keys line");
                let (key0, key1) = filter.keys();
                assert_eq!(format!("keys {key0} {key1}"), want_keys, "reset keys");
                check_state(filter, lines.next().expect("state line"));
                counts[5] += 1;
            }
            "done" => break,
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [5, 96, 15, 18, 9, 1], "row counts");
}
