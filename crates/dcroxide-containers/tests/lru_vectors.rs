// SPDX-License-Identifier: ISC
//! Replay of dcrd's LRU map and set behavior generated inside dcrd's
//! container/lru package over a mock clock
//! (`data/lru_vectors.txt`): recency ordering, eviction at the
//! limit, updates in place, the hit ratio bit for bit, default and
//! per-item TTLs including the never-expire zero TTL, the
//! invisibility of expired-but-unscanned items, the 30-second lazy
//! expiration scans, immediate eviction, clearing, and the set
//! wrapper — comparing the length, LRU-to-MRU key and value order,
//! and every eviction count after each operation.

// Test-harness arithmetic over bounded lengths.
#![allow(clippy::arithmetic_side_effects)]

use core::cell::Cell;
use std::rc::Rc;

use dcroxide_containers::lru::{Map, Set};

enum Container {
    Map(Map<String, String>),
    Set(Set<String>),
}

fn csv(items: &[String]) -> String {
    if items.is_empty() {
        return "-".to_string();
    }
    items.join(",")
}

impl Container {
    fn state(&self) -> String {
        match self {
            Container::Map(m) => format!(
                "state {} {} {} {:016x}",
                m.len(),
                csv(&m.keys()),
                csv(&m.values()),
                m.hit_ratio().to_bits()
            ),
            Container::Set(s) => format!(
                "state {} {} - {:016x}",
                s.len(),
                csv(&s.items()),
                s.hit_ratio().to_bits()
            ),
        }
    }

    fn as_map(&mut self) -> &mut Map<String, String> {
        match self {
            Container::Map(m) => m,
            Container::Set(_) => panic!("expected a map scenario"),
        }
    }

    fn as_set(&mut self) -> &mut Set<String> {
        match self {
            Container::Set(s) => s,
            Container::Map(_) => panic!("expected a set scenario"),
        }
    }
}

#[test]
fn lru_vectors() {
    let data = include_str!("data/lru_vectors.txt");
    let mut lines = data.lines().peekable();

    let clock = Rc::new(Cell::new(0i64));
    let now_fn: Rc<dyn Fn() -> i64> = {
        let clock = clock.clone();
        Rc::new(move || clock.get())
    };

    let mut container: Option<Container> = None;
    let mut counts = [0usize; 6];

    macro_rules! check_state {
        ($ctx:expr) => {
            let got = container.as_ref().expect("container").state();
            let want = lines.next().expect("state line");
            assert_eq!(got, want, "state after {}", $ctx);
        };
    }
    macro_rules! check_ev {
        ($ev:expr, $ctx:expr) => {
            let want = lines.next().expect("ev line");
            assert_eq!(format!("ev {}", $ev), want, "{}", $ctx);
        };
    }

    while let Some(line) = lines.next() {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "clock" => clock.set(f[1].parse().expect("clock")),
            "mapnew" => {
                let limit: u32 = f[1].parse().expect("limit");
                let ttl: i64 = f[2].parse().expect("ttl");
                let m = if ttl == 0 {
                    Map::new_with_clock(limit, now_fn.clone())
                } else {
                    Map::new_with_default_ttl_and_clock(limit, ttl, now_fn.clone())
                };
                container = Some(Container::Map(m));
                check_state!(line);
                counts[0] += 1;
            }
            "setnew" => {
                let limit: u32 = f[1].parse().expect("limit");
                let ttl: i64 = f[2].parse().expect("ttl");
                let s = if ttl == 0 {
                    Set::new_with_clock(limit, now_fn.clone())
                } else {
                    Set::new_with_default_ttl_and_clock(limit, ttl, now_fn.clone())
                };
                container = Some(Container::Set(s));
                check_state!(line);
                counts[0] += 1;
            }
            "put" => {
                let ev = container
                    .as_mut()
                    .expect("container")
                    .as_map()
                    .put(f[1].to_string(), f[2].to_string());
                check_ev!(ev, line);
                check_state!(line);
                counts[1] += 1;
            }
            "putttl" => {
                let ttl: i64 = f[3].parse().expect("ttl");
                let ev = container
                    .as_mut()
                    .expect("container")
                    .as_map()
                    .put_with_ttl(f[1].to_string(), f[2].to_string(), ttl);
                check_ev!(ev, line);
                check_state!(line);
                counts[1] += 1;
            }
            "get" => {
                let got = container
                    .as_mut()
                    .expect("container")
                    .as_map()
                    .get(&f[1].to_string());
                let want = lines.next().expect("got line");
                let rendered = match &got {
                    Some(value) => format!("got {value} true"),
                    None => "got - false".to_string(),
                };
                assert_eq!(rendered, want, "{line}");
                check_state!(line);
                counts[2] += 1;
            }
            "peek" => {
                let got = container
                    .as_mut()
                    .expect("container")
                    .as_map()
                    .peek(&f[1].to_string());
                let want = lines.next().expect("got line");
                let rendered = match &got {
                    Some(value) => format!("got {value} true"),
                    None => "got - false".to_string(),
                };
                assert_eq!(rendered, want, "{line}");
            }
            "exists" => {
                let got = container
                    .as_mut()
                    .expect("container")
                    .as_map()
                    .exists(&f[1].to_string());
                let want = lines.next().expect("is line");
                assert_eq!(format!("is {got}"), want, "{line}");
                counts[3] += 1;
            }
            "delete" => {
                container
                    .as_mut()
                    .expect("container")
                    .as_map()
                    .delete(&f[1].to_string());
                check_state!(line);
            }
            "evictnow" => {
                let ev = match container.as_mut().expect("container") {
                    Container::Map(m) => m.evict_expired_now(),
                    Container::Set(s) => s.evict_expired_now(),
                };
                check_ev!(ev, line);
                check_state!(line);
                counts[4] += 1;
            }
            "clear" => {
                match container.as_mut().expect("container") {
                    Container::Map(m) => m.clear(),
                    Container::Set(s) => s.clear(),
                }
                check_state!(line);
            }
            "sput" => {
                let ev = container
                    .as_mut()
                    .expect("container")
                    .as_set()
                    .put(f[1].to_string());
                check_ev!(ev, line);
                check_state!(line);
                counts[5] += 1;
            }
            "sputttl" => {
                let ttl: i64 = f[2].parse().expect("ttl");
                let ev = container
                    .as_mut()
                    .expect("container")
                    .as_set()
                    .put_with_ttl(f[1].to_string(), ttl);
                check_ev!(ev, line);
                check_state!(line);
                counts[5] += 1;
            }
            "scontains" => {
                let got = container
                    .as_mut()
                    .expect("container")
                    .as_set()
                    .contains(&f[1].to_string());
                let want = lines.next().expect("is line");
                assert_eq!(format!("is {got}"), want, "{line}");
                check_state!(line);
            }
            "sexists" => {
                let got = container
                    .as_mut()
                    .expect("container")
                    .as_set()
                    .exists(&f[1].to_string());
                let want = lines.next().expect("is line");
                assert_eq!(format!("is {got}"), want, "{line}");
            }
            "sdelete" => {
                container
                    .as_mut()
                    .expect("container")
                    .as_set()
                    .delete(&f[1].to_string());
                check_state!(line);
            }
            "done" => break,
            other => panic!("unknown row tag {other}"),
        }
    }
    assert_eq!(counts, [6, 17, 9, 5, 3, 8], "row counts");
}
