// Bitcoin secp256k1 bindings
// Written in 2014 by
//   Dawid Ciężarkiewicz
//   Andrew Poelstra
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! # Secp256k1
//! Rust bindings for Pieter Wuille's secp256k1 library, which is used for
//! fast and accurate manipulation of ECDSA signatures on the secp256k1
//! curve. Such signatures are used extensively by the Bitcoin network
//! and its derivatives.
//!

#![crate_type = "lib"]
#![crate_type = "rlib"]
#![crate_type = "dylib"]
#![crate_name = "secp256k1zkp"]
// Coding conventions
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]
#![cfg_attr(feature = "dev", allow(unstable_features))]
#![cfg_attr(feature = "dev", feature(plugin))]
#![cfg_attr(feature = "dev", plugin(clippy))]
#![cfg_attr(all(test, feature = "unstable"), feature(test))]
#[cfg(all(test, feature = "unstable"))]
extern crate test;
extern crate serde_json as json;

#[macro_use]
mod macros;
pub mod aggsig;
pub mod constants;
pub mod ecdh;
pub mod ffi;
pub mod key;
pub mod pedersen;
pub mod secp_ser;
mod types;

pub use aggsig::{
    add_signatures_single, export_secnonce_single, sign_single, verify_batch, verify_single,
    AggSigContext, ZERO_256,
};
pub use constants::{
    AGG_SIGNATURE_SIZE, BULLET_PROOF_MSG_SIZE, COMPACT_SIGNATURE_SIZE, COMPRESSED_PUBLIC_KEY_SIZE,
    CURVE_ORDER, GENERATOR_G, GENERATOR_H, GENERATOR_PUB_J_RAW, GENERATOR_SIZE, MAX_PROOF_SIZE,
    MESSAGE_SIZE, PEDERSEN_COMMITMENT_SIZE, PEDERSEN_COMMITMENT_SIZE_INTERNAL, PROOF_MSG_SIZE,
    PUBLIC_KEY_SIZE, RECOVERABLE_AGG_SIGNATURE_SIZE, SECRET_KEY_SIZE, SINGLE_BULLET_PROOF_SIZE,
    UNCOMPRESSED_PUBLIC_KEY_SIZE,
};
pub use ecdh::SharedSecret;
pub use key::{PublicKey, SecretKey, ONE_KEY, ZERO_KEY};
pub use pedersen::{Commitment, ProofInfo, ProofMessage, ProofRange, RangeProof};
pub use secp_ser::{
    hex_to_bp, hex_to_commit, hex_to_key, hex_to_rsig, hex_to_sig, hex_to_u8, option_sig_serde,
    pubkey_serde, pubkey_uncompressed_serde, seckey_serde, sig_serde, u8_to_hex,
};
pub use types::{
    AggSigPartialSignature, ContextFlag, Error, Message, RecoverableSignature, RecoveryId,
    Secp256k1, Signature,
};