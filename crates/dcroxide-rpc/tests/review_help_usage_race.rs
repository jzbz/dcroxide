// SPDX-License-Identifier: ISC
//! The help usage cache under a cold-cache race.
//!
//! dcrd's `helpCacher.RPCUsage` holds the cacher's mutex across the
//! whole generation (`rpcserverhelp.go:1094-1126`), so the first caller
//! to take it caches the usage for its own websocket flag and a racing
//! caller waits and receives that same text (QK-0005).  The port used
//! to drop the lock while generating and overwrite the cache on the way
//! out: two racing callers with different flags each returned their own
//! variant, and the cache kept whichever finished last.

use std::sync::{Arc, Barrier};
use std::thread;

use dcroxide_dcrjson::Registry;
use dcroxide_rpc::HelpCacher;
use dcroxide_rpctypes::register_all;

#[test]
fn racing_callers_on_a_cold_cache_agree_on_one_usage_text() {
    let mut registry = Registry::new();
    register_all(&mut registry);
    let registry = Arc::new(registry);

    // The two variants really differ, or the race proves nothing.
    let without_ws = HelpCacher::new()
        .rpc_usage(&registry, false)
        .expect("usage");
    let with_ws = HelpCacher::new().rpc_usage(&registry, true).expect("usage");
    assert_ne!(without_ws, with_ws);

    for round in 0..200 {
        let cacher = Arc::new(HelpCacher::new());
        let start = Arc::new(Barrier::new(2));
        let callers: Vec<_> = [false, true]
            .into_iter()
            .map(|include_websockets| {
                let (cacher, registry, start) = (cacher.clone(), registry.clone(), start.clone());
                thread::spawn(move || {
                    start.wait();
                    cacher
                        .rpc_usage(&registry, include_websockets)
                        .expect("usage")
                })
            })
            .collect();
        let got: Vec<String> = callers
            .into_iter()
            .map(|c| c.join().expect("caller"))
            .collect();

        assert_eq!(got[0], got[1], "round {round}: the racing callers disagree");
        assert!(got[0] == without_ws || got[0] == with_ws);
        let cached = cacher.rpc_usage(&registry, false).expect("usage");
        assert_eq!(
            cached, got[0],
            "round {round}: the cache holds another variant than the callers returned"
        );
    }
}
