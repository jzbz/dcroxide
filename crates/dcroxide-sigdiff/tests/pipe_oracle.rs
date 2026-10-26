// SPDX-License-Identifier: ISC
//! The pipe against the real oracle: `build_info` names the signature
//! modules, and thousands of requests in flight come back in order, each
//! answer the one its request asked for.

use std::sync::{Arc, Mutex};

use dcroxide_sigdiff::cmd::{Cmd, Request};
use dcroxide_sigdiff::manifest::{SIGNATURE_MODULES, check_pin};
use dcroxide_sigdiff::pipe::{OraclePipe, Payload, PipeConfig};
use dcroxide_sigdiff::reply::Reply;
use dcroxide_testutil::{SplitMix64, hex, oracle_bin_or_skip};

/// A case: a sequence number and its requests.
struct Numbered(u64, Vec<Request>);

impl Payload for Numbered {
    fn requests(&self) -> &[Request] {
        &self.1
    }
}

/// Every case answered, with its replies, in the order they came back.
type Answered = Arc<Mutex<Vec<(Numbered, Vec<Reply>)>>>;

/// What the oracle must answer `request` with: BLAKE-256 of the data, or
/// the hash's display string (its bytes reversed, in hex).
fn expected(request: &Request) -> String {
    match request.cmd {
        Cmd::Blake256 => hex(&dcroxide_crypto::blake256::sum256(&request.data)),
        Cmd::HashString => {
            let mut reversed = request.data.clone();
            reversed.reverse();
            hex(&reversed)
        }
        other => panic!("{other:?} is not a pipe test command"),
    }
}

#[test]
fn requests_in_flight_come_back_in_order() {
    let Some(bin) = oracle_bin_or_skip() else {
        return;
    };
    let mut rng = SplitMix64::from_entropy("sigdiff pipe_oracle");
    let cfg = PipeConfig {
        window: 64,
        ..PipeConfig::new(bin)
    };
    let seen: Answered = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    let mut pipe = OraclePipe::spawn(&cfg, move |case: Numbered, replies: Vec<Reply>| {
        sink.lock().expect("lock").push((case, replies));
    })
    .unwrap_or_else(|_| panic!("the oracle starts"));

    let info = pipe.build_info().clone();
    assert!(info.go_version.is_some(), "{}", info.raw);
    for module in SIGNATURE_MODULES {
        assert!(info.modules.contains_key(module), "{}", info.raw);
    }
    assert!(
        check_pin(&info).consistent(),
        "{:?}",
        check_pin(&info).problems()
    );

    // The empty input's digest, dcrd's known value.
    let empty = Numbered(
        0,
        vec![Request {
            cmd: Cmd::Blake256,
            data: Vec::new(),
        }],
    );
    assert!(pipe.submit(empty).is_ok());
    let mut requests = 1usize;
    let mut n = 1u64;
    while requests < 10_000 {
        let k = usize::try_from(rng.below(3))
            .expect("small")
            .saturating_add(1);
        let case: Vec<Request> = (0..k)
            .map(|_| {
                if rng.below(2) == 0 {
                    Request {
                        cmd: Cmd::Blake256,
                        data: rng.bytes(200),
                    }
                } else {
                    let mut data = vec![0u8; 32];
                    rng.fill(&mut data);
                    Request {
                        cmd: Cmd::HashString,
                        data,
                    }
                }
            })
            .collect();
        requests = requests.saturating_add(k);
        assert!(pipe.submit(Numbered(n, case)).is_ok());
        n = n.saturating_add(1);
    }
    assert!(pipe.finish().is_ok());

    let seen = seen.lock().expect("lock");
    assert_eq!(seen.len(), usize::try_from(n).expect("small"));
    assert_eq!(
        seen[0].1[0].result.as_deref(),
        Some("716f6e863f744b9ac22c97ec7b76ea5f5908bc5b2f67c61510bfc4751384ea7a")
    );
    let mut id = 0u64;
    for (i, (case, replies)) in seen.iter().enumerate() {
        assert_eq!(case.0, u64::try_from(i).expect("small"), "in order");
        assert_eq!(replies.len(), case.1.len());
        for (request, reply) in case.1.iter().zip(replies) {
            assert_eq!(reply.id, Some(id), "ids count up");
            assert_eq!(reply.result.as_deref(), Some(expected(request).as_str()));
            id = id.saturating_add(1);
        }
    }
}
