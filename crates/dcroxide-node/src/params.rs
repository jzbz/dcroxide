// SPDX-License-Identifier: ISC
//! The per-network parameter groupings of dcrd's `params.go`: the
//! chain parameters paired with the JSON-RPC listen port.

use dcroxide_chaincfg::{Params, mainnet_params, regnet_params, simnet_params, testnet3_params};

/// Which network the configuration selected; dcrd compares its
/// `params` pointers for the same purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveNet {
    /// The main network.
    MainNet,
    /// The test network (version 3).
    TestNet3,
    /// The simulation test network.
    SimNet,
    /// The regression test network.
    RegNet,
}

/// Parameters for a network grouped with the RPC port (dcrd
/// `params`).  The RPC port is intentionally different from the
/// reference implementation because dcrd does not handle wallet
/// requests.
#[derive(Clone)]
pub struct NodeParams {
    /// The chain parameters.
    pub params: Params,
    /// The JSON-RPC default listen port.
    pub rpc_port: &'static str,
    /// The selected network.
    pub net: ActiveNet,
}

impl NodeParams {
    /// The main network parameters (dcrd `mainNetParams`).
    pub fn main_net() -> NodeParams {
        NodeParams {
            params: mainnet_params(),
            rpc_port: "9109",
            net: ActiveNet::MainNet,
        }
    }

    /// The test network (version 3) parameters (dcrd
    /// `testNet3Params`).
    pub fn test_net3() -> NodeParams {
        NodeParams {
            params: testnet3_params(),
            rpc_port: "19109",
            net: ActiveNet::TestNet3,
        }
    }

    /// The simulation test network parameters (dcrd
    /// `simNetParams`).
    pub fn sim_net() -> NodeParams {
        NodeParams {
            params: simnet_params(),
            rpc_port: "19556",
            net: ActiveNet::SimNet,
        }
    }

    /// The regression test network parameters (dcrd
    /// `regNetParams`).
    pub fn reg_net() -> NodeParams {
        NodeParams {
            params: regnet_params(),
            rpc_port: "18656",
            net: ActiveNet::RegNet,
        }
    }
}
