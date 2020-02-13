// Rust secp256k1 bindings for Schnorr signature functions
//
// 2019 The Gotts Developers
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

//! # Schnorr Signature Functionality

use rand::{thread_rng, Rng};
use std::ptr;

use crate::aggsig::SCRATCH_SPACE_SIZE;
use crate::ffi;
use crate::key::{PublicKey, SecretKey};
use crate::Secp256k1;
use crate::{ComSignature, Error, Message, Signature, ZERO_256};

/// Create a Schnorr signature.
/// Returns: Ok(Signature) on success
/// In:
/// msg: the message to sign
/// seckey: the secret key
pub fn schnorrsig_sign(
    secp: &Secp256k1,
    msg: &Message,
    seckey: &SecretKey,
) -> Result<Signature, Error> {
    let mut retsig = Signature::from(ffi::Signature::new());
    let mut nonce_is_negated: i64 = 0;

    let retval = unsafe {
        ffi::secp256k1_schnorrsig_sign(
            secp.ctx,
            retsig.as_mut_ptr(),
            &mut nonce_is_negated,
            msg.as_ptr(),
            seckey.as_ptr(),
            ptr::null(),
            ptr::null(),
        )
    };
    if retval == 0 {
        return Err(Error::InvalidSignature);
    }
    Ok(retsig)
}

/// Verify a Schnorr signature.
/// Returns: true on success
/// In:
/// sig: The signature
/// msg: the message to verify
/// pubkey: the public key
pub fn schnorrsig_verify(
    secp: &Secp256k1,
    sig: &Signature,
    msg: &Message,
    pubkey: &PublicKey,
) -> bool {
    let retval = unsafe {
        ffi::secp256k1_schnorrsig_verify(secp.ctx, sig.as_ptr(), msg.as_ptr(), pubkey.as_ptr())
    };
    match retval {
        0 => false,
        1 => true,
        _ => false,
    }
}

/// Create a ComSig signature.
/// Returns: Ok(CommitSignature) on success
/// In:
/// msg: the message to sign
/// seckey: the secret key
pub fn comsig_sign(
    secp: &Secp256k1,
    msg: &Message,
    seckey: &SecretKey,
    value: &SecretKey,
    pubkey: &mut Option<PublicKey>,
) -> Result<ComSignature, Error> {
    let mut retsig = ComSignature::from(ffi::ComSignature::new());
    let mut nonce_is_negated: i64 = 0;
    let ret_pubkey = if let Some(pk) = pubkey {
        pk.as_mut_ptr()
    } else {
        ptr::null_mut()
    };
    let mut seed = [0u8; 16];
    thread_rng().fill(&mut seed);

    let retval = unsafe {
        ffi::secp256k1_comsig_sign(
            secp.ctx,
            retsig.as_mut_ptr(),
            ret_pubkey,
            &mut nonce_is_negated,
            msg.as_ptr(),
            seckey.as_ptr(),
            value.as_ptr(),
            ptr::null(),
            seed.as_ptr(),
        )
    };
    if retval == 0 {
        return Err(Error::InvalidSignature);
    }
    Ok(retsig)
}

/// Verify a ComSig signature.
/// Returns: true on success
/// In:
/// sig: The signature
/// msg: the message to verify
/// pubkey: the public key
pub fn comsig_verify(
    secp: &Secp256k1,
    sig: &ComSignature,
    msg: &Message,
    pubkey: &PublicKey,
) -> bool {
    let retval = unsafe {
        ffi::secp256k1_comsig_verify(secp.ctx, sig.as_ptr(), msg.as_ptr(), pubkey.as_ptr())
    };
    match retval {
        0 => false,
        1 => true,
        _ => false,
    }
}

/// Batch Schnorr signature verification
/// Returns: true on success
/// In:
/// sigs: The signatures
/// msg: The messages to verify
/// pubkey: The public keys
pub fn verify_batch(
    secp: &Secp256k1,
    sigs: &Vec<Signature>,
    msgs: &Vec<Message>,
    pub_keys: &Vec<PublicKey>,
) -> bool {
    if sigs.len() != msgs.len() || sigs.len() != pub_keys.len() {
        return false;
    }

    for i in 0..pub_keys.len() {
        if (pub_keys[i].0).0.starts_with(&ZERO_256) {
            return false;
        }
    }

    let sigs_vec = map_vec!(sigs, |s| s.0.as_ptr());
    let msgs_vec = map_vec!(msgs, |m| m.as_ptr());
    let pub_keys_vec = map_vec!(pub_keys, |pk| pk.as_ptr());

    unsafe {
        let scratch = ffi::secp256k1_scratch_space_create(secp.ctx, SCRATCH_SPACE_SIZE);
        let result = ffi::secp256k1_schnorrsig_verify_batch(
            secp.ctx,
            scratch,
            sigs_vec.as_ptr(),
            msgs_vec.as_ptr(),
            pub_keys_vec.as_ptr(),
            sigs.len(),
        );
        ffi::secp256k1_scratch_space_destroy(scratch);
        result == 1
    }
}

#[cfg(test)]
mod tests {
    use super::{
        comsig_sign, comsig_verify, schnorrsig_sign, schnorrsig_verify, verify_batch, Secp256k1,
    };
    use crate::key::PublicKey;
    use crate::{ContextFlag, SecretKey};
    use crate::{Message, Signature};

    use rand::{thread_rng, Rng};

    #[test]
    fn test_schnorrsig_sign() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!(
            "Performing test_schnorrsig_sign with seckey, pubkey: {:?},{:?}",
            sk, pk
        );

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let sig = schnorrsig_sign(&secp, &msg, &sk).unwrap();
        let der = sig.serialize_der();
        println!(
            "schnorr signature len: {}, der: {}",
            der.len(),
            hex::encode(der.clone())
        );

        println!(
            "Verifying Schnorr Signature: {:?}, msg: {:?}, pk:{:?}",
            sig, msg, pk
        );
        let result = schnorrsig_verify(&secp, &sig, &msg, &pk);
        println!("Signature verification (correct): {}", result);
        assert_eq!(result, true);
    }

    #[test]
    fn test_comsig_sign() {
        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();

        println!(
            "Performing test_comsig_sign with seckey, pubkey: {:?},{:?}",
            sk, pk
        );

        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let w = SecretKey::new(&mut thread_rng());
        let msg = Message::from_slice(&msg).unwrap();
        let mut ret_pubkey = Some(PublicKey::new());
        let sig = comsig_sign(&secp, &msg, &sk, &w, &mut ret_pubkey).unwrap();
        println!("ComSig signature data: {}", hex::encode(sig.0));

        let commit = secp.commit_blind(&w, &sk).unwrap();
        let commit_pk = commit.to_pubkey(&secp).unwrap();
        assert_eq!(ret_pubkey.unwrap(), commit_pk);

        println!(
            "Verifying ComSig signature: {:?}, msg: {:?}, commit:{:?}",
            sig, msg, commit
        );
        let result = comsig_verify(&secp, &sig, &msg, &commit_pk);
        println!("Commit Signature verification (correct): {}", result);
        assert_eq!(result, true);

        let num = 4096;
        for _ in 0..num {
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();
            let w = SecretKey::new(&mut thread_rng());
            let sig = comsig_sign(&secp, &msg, &sk, &w, &mut ret_pubkey).unwrap();

            let commit = secp.commit_blind(&w, &sk).unwrap();
            let commit_pk = commit.to_pubkey(&secp).unwrap();
            assert_eq!(ret_pubkey.unwrap(), commit_pk);

            let result = comsig_verify(&secp, &sig, &msg, &commit_pk);
            assert_eq!(result, true);
        }
    }

    #[test]
    fn test_aggsig_batch() {
        let secp = Secp256k1::with_caps(ContextFlag::Full);

        let mut sigs: Vec<Signature> = vec![];
        let mut msgs: Vec<Message> = vec![];
        let mut pub_keys: Vec<PublicKey> = vec![];

        for _ in 0..100 {
            let (sk, pk) = secp.generate_keypair(&mut thread_rng()).unwrap();
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);

            let msg = Message::from_slice(&msg).unwrap();
            let sig = schnorrsig_sign(&secp, &msg, &sk).unwrap();

            let result_single = schnorrsig_verify(&secp, &sig, &msg, &pk);
            assert_eq!(result_single, true);

            pub_keys.push(pk);
            msgs.push(msg);
            sigs.push(sig);
        }

        println!("Verifying Schnorr signature batch of 100");
        let result = verify_batch(&secp, &sigs, &msgs, &pub_keys);
        assert_eq!(result, true);
    }
}
