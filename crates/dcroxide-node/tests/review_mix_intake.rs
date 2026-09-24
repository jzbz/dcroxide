// SPDX-License-Identifier: ISC
//! X1-c#5 (with PW10#13): the input loop hashes a received mix message
//! once, by reference, and hands that hash to the server handler along
//! with the message itself, the way dcrd's `readMessage` caches
//! `WriteHash` on the message for `onMixMessage` to read back.  Before,
//! the loop deep-copied the message to hash it for the stall detector
//! alone, and the handler copied and hashed it again.

use std::sync::Mutex;

use dcroxide_chainhash::Hash;
use dcroxide_node::peerconn::NodePeerEnv;
use dcroxide_node::peerloop::{OutboundQueue, ServeHooks, ServeSignal, run_peer_input};
use dcroxide_peer::{Config, MsgTransport, Peer, ReadError};
use dcroxide_wire::{Message, MsgMixSecrets};

/// Hands out a fixed run of messages, then reports the connection gone.
struct ScriptedTransport(std::vec::IntoIter<Message>);

impl MsgTransport for ScriptedTransport {
    fn read_message(&mut self) -> Result<Message, ReadError> {
        self.0.next().ok_or_else(|| ReadError::io("end of script"))
    }
    fn write_message(&mut self, _msg: &Message) -> Result<(), String> {
        Ok(())
    }
}

/// Records each command the handler saw with the hash it was handed.
#[derive(Default)]
struct Recorder(Vec<(&'static str, Option<Hash>)>);

impl ServeHooks for Recorder {
    fn on_message(
        &mut self,
        _peer: &Mutex<Peer>,
        msg: Message,
        mix_hash: Option<Hash>,
        _outbound: &OutboundQueue,
    ) -> ServeSignal {
        self.0.push((msg.command(), mix_hash));
        ServeSignal::Continue
    }
}

fn secrets(n: u8) -> MsgMixSecrets {
    MsgMixSecrets {
        signature: [1; 64],
        identity: [2; 33],
        session_id: [3; 32],
        run: 0,
        seed: [n; 32],
        slot_reserve_msgs: vec![vec![5; 20]],
        dc_net_msgs: Vec::new(),
        seen_secrets: Vec::new(),
    }
}

#[test]
fn the_handler_receives_the_mix_hash_the_input_loop_computed() {
    let delayed = secrets(4);
    let steady = secrets(6);
    let delayed_hash = delayed.mix_hash().expect("hash");
    let steady_hash = steady.mix_hash().expect("hash");

    let peer = Mutex::new(Peer::new_inbound(Config::default()));
    let (queue, _outbound) = OutboundQueue::channel();
    let mut transport =
        ScriptedTransport(vec![Message::GetAddr, Message::MixSecrets(steady)].into_iter());
    let mut recorder = Recorder::default();
    run_peer_input(
        &peer,
        &mut transport,
        &mut NodePeerEnv::new(),
        &queue,
        &mut recorder,
        vec![Message::MixSecrets(delayed)],
    );

    assert_eq!(
        recorder.0,
        vec![
            // A message a legacy peer sent before its verack was read,
            // and hashed, during the handshake.
            ("mixsecrets", Some(delayed_hash)),
            ("getaddr", None),
            ("mixsecrets", Some(steady_hash)),
        ]
    );
}
