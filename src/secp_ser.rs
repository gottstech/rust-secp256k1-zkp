// Copyright 2018 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Sane serialization & deserialization of cryptographic structures into hex

use crate::{
    AGG_SIGNATURE_SIZE, MAX_PROOF_SIZE, PEDERSEN_COMMITMENT_SIZE, RECOVERABLE_AGG_SIGNATURE_SIZE,
    SECRET_KEY_SIZE,
};
use serde::{self, Deserialize, Deserializer, Serializer};
use std::fmt;

struct ExpectedString(pub String);

impl serde::de::Expected for ExpectedString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Creates a [u8; SECRET_KEY_SIZE] from a hex string
pub fn hex_to_key<'de, D>(deserializer: D) -> Result<[u8; SECRET_KEY_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|string| {
            hex::decode(string).map_err(|err| serde::de::Error::custom(err.to_string()))
        })
        .and_then(|bytes: Vec<u8>| {
            let mut ret = [0u8; SECRET_KEY_SIZE];
            match bytes.len() {
                SECRET_KEY_SIZE => ret[..].copy_from_slice(&bytes),
                _ => Err(serde::de::Error::invalid_length(
                    bytes.len(),
                    &ExpectedString("a 32-byte hex string".to_owned()),
                ))?,
            }
            Ok(ret)
        })
}

/// Creates a [u8; AGG_SIGNATURE_SIZE] from a hex string
pub fn hex_to_sig<'de, D>(deserializer: D) -> Result<[u8; AGG_SIGNATURE_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|bytes: Vec<u8>| {
            let mut ret = [0u8; AGG_SIGNATURE_SIZE];
            match bytes.len() {
                AGG_SIGNATURE_SIZE => ret[..].copy_from_slice(&bytes),
                _ => Err(serde::de::Error::invalid_length(
                    bytes.len(),
                    &ExpectedString("a 64-byte hex string".to_owned()),
                ))?,
            }
            Ok(ret)
        })
}

/// Creates a [u8; RECOVERABLE_AGG_SIGNATURE_SIZE] from a hex string
pub fn hex_to_rsig<'de, D>(
    deserializer: D,
) -> Result<[u8; RECOVERABLE_AGG_SIGNATURE_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|bytes: Vec<u8>| {
            let mut ret = [0u8; RECOVERABLE_AGG_SIGNATURE_SIZE];
            match bytes.len() {
                RECOVERABLE_AGG_SIGNATURE_SIZE => ret[..].copy_from_slice(&bytes),
                _ => Err(serde::de::Error::invalid_length(
                    bytes.len(),
                    &ExpectedString("a 65-byte hex string".to_owned()),
                ))?,
            }
            Ok(ret)
        })
}

/// Creates a [u8; PEDERSEN_COMMITMENT_SIZE] from a hex string
pub fn hex_to_commit<'de, D>(deserializer: D) -> Result<[u8; PEDERSEN_COMMITMENT_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|bytes: Vec<u8>| {
            let mut ret = [0u8; PEDERSEN_COMMITMENT_SIZE];
            match bytes.len() {
                PEDERSEN_COMMITMENT_SIZE => ret[..].copy_from_slice(&bytes),
                _ => Err(serde::de::Error::invalid_length(
                    bytes.len(),
                    &ExpectedString("a 33-byte hex string".to_owned()),
                ))?,
            }
            Ok(ret)
        })
}

/// Creates a [u8; MAX_PROOF_SIZE] from a hex string
pub fn hex_to_bp<'de, D>(deserializer: D) -> Result<[u8; MAX_PROOF_SIZE], D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|bytes: Vec<u8>| {
            let mut ret = [0u8; MAX_PROOF_SIZE];
            match bytes.len() {
                MAX_PROOF_SIZE => ret[..].copy_from_slice(&bytes),
                _ => Err(serde::de::Error::invalid_length(
                    bytes.len(),
                    &ExpectedString("a 675-byte hex string".to_owned()),
                ))?,
            }
            Ok(ret)
        })
}

/// Creates a Vec<u8> from a hex string
pub fn hex_to_u8<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    String::deserialize(deserializer)
        .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
        .and_then(|bytes: Vec<u8>| Ok(bytes))
}

/// Serializes a [u8] into a hex string
pub fn u8_to_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(&bytes[..]))
}

/// Serializes a secp SecretKey to and from hex
pub mod seckey_serde {
    use crate::static_secp_instance;
    use crate::SecretKey;
    use serde::{Deserialize, Deserializer, Serializer};

    ///
    pub fn serialize<S>(key: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.0))
    }

    ///
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let static_secp = static_secp_instance();
        String::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
            .and_then(|bytes: Vec<u8>| {
                SecretKey::from_slice(&static_secp, &bytes)
                    .map_err(|err| Error::custom(err.to_string()))
            })
    }
}

/// Serializes a secp PublicKey to and from hex
pub mod pubkey_serde {
    use crate::{static_secp_instance, PublicKey};
    use serde::{Deserialize, Deserializer, Serializer};

    ///
    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let static_secp = static_secp_instance();
        serializer.serialize_str(&hex::encode(key.serialize_vec(&static_secp, true)))
    }

    ///
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let static_secp = static_secp_instance();
        String::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
            .and_then(|bytes: Vec<u8>| {
                PublicKey::from_slice(&static_secp, &bytes)
                    .map_err(|err| Error::custom(err.to_string()))
            })
    }
}

/// Serializes a secp PublicKey to and from hex
pub mod pubkey_uncompressed_serde {
    use crate::{static_secp_instance, PublicKey};
    use serde::{Deserialize, Deserializer, Serializer};

    ///
    pub fn serialize<S>(key: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let static_secp = static_secp_instance();
        serializer.serialize_str(&hex::encode(key.serialize_vec(&static_secp, false)))
    }

    ///
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error;
        let static_secp = static_secp_instance();
        String::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
            .and_then(|bytes: Vec<u8>| {
                PublicKey::from_slice(&static_secp, &bytes)
                    .map_err(|err| Error::custom(err.to_string()))
            })
    }
}

/// Serializes an Option<secp::Signature> to and from hex
pub mod option_sig_serde {
    use crate::static_secp_instance;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    ///
    pub fn serialize<S>(sig: &Option<crate::Signature>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let static_secp = static_secp_instance();
        match sig {
            Some(sig) => {
                serializer.serialize_str(&hex::encode(sig.serialize_compact(&static_secp).to_vec()))
            }
            None => serializer.serialize_none(),
        }
    }

    ///
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<crate::Signature>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let static_secp = static_secp_instance();
        Option::<String>::deserialize(deserializer).and_then(|res| match res {
            Some(string) => hex::decode(string.to_string())
                .map_err(|err| Error::custom(err.to_string()))
                .and_then(|bytes: Vec<u8>| {
                    let mut b = [0u8; 64];
                    b.copy_from_slice(&bytes[0..64]);
                    crate::Signature::from_compact(&static_secp, &b)
                        .map(|val| Some(val))
                        .map_err(|err| Error::custom(err.to_string()))
                }),
            None => Ok(None),
        })
    }
}

/// Serializes a secp::Signature to and from hex
pub mod sig_serde {
    use crate::static_secp_instance;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    ///
    pub fn serialize<S>(sig: &crate::Signature, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let static_secp = static_secp_instance();
        serializer.serialize_str(&hex::encode(sig.serialize_compact(&static_secp).to_vec()))
    }

    ///
    pub fn deserialize<'de, D>(deserializer: D) -> Result<crate::Signature, D::Error>
    where
        D: Deserializer<'de>,
    {
        let static_secp = static_secp_instance();
        String::deserialize(deserializer)
            .and_then(|string| hex::decode(string).map_err(|err| Error::custom(err.to_string())))
            .and_then(|bytes: Vec<u8>| {
                let mut b = [0u8; 64];
                b.copy_from_slice(&bytes[0..64]);
                crate::Signature::from_compact(&static_secp, &b)
                    .map_err(|err| Error::custom(err.to_string()))
            })
    }
}

// Test serialization methods of components that are being used
#[cfg(test)]
mod test {
    use super::*;
    use crate::sign_single;
    use crate::{Commitment, Message, Signature};
    use crate::{ContextFlag, Secp256k1};
    use crate::{PublicKey, SecretKey};

    use serde::{self, Deserialize, Serialize};
    use serde_json;

    use rand::{thread_rng, Rng};

    #[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
    struct SerTest {
        #[serde(with = "pubkey_serde")]
        pub pub_key: PublicKey,
        #[serde(with = "option_sig_serde")]
        pub opt_sig: Option<Signature>,
        #[serde(with = "sig_serde")]
        pub sig: Signature,
        pub seckey2: SecretKey,
        pub pubkey2: PublicKey,
        pub sig2: Signature,
        pub commit2: Commitment,
        pub commit_vec2: Vec<Commitment>,
        #[serde(with = "pubkey_uncompressed_serde")]
        pub pubkey3: PublicKey,
    }

    impl SerTest {
        pub fn random() -> SerTest {
            let secp = Secp256k1::with_caps(ContextFlag::Commit);
            let sk = SecretKey::new(&secp, &mut thread_rng());
            let mut msg = [0u8; 32];
            thread_rng().fill(&mut msg);
            let msg = Message::from_slice(&msg).unwrap();
            let sig = sign_single(&secp, &msg, &sk, None, None, None, None, None).unwrap();
            SerTest {
                pub_key: PublicKey::from_secret_key(&secp, &sk).unwrap(),
                opt_sig: Some(sig.clone()),
                sig: sig.clone(),
                seckey2: sk.clone(),
                pubkey2: PublicKey::from_secret_key(&secp, &sk).unwrap(),
                sig2: sig.clone(),
                commit2: secp.commit(100u64, sk.clone()).unwrap(),
                commit_vec2: vec![
                    secp.commit(200u64, sk.clone()).unwrap(),
                    secp.commit(300u64, sk.clone()).unwrap(),
                ],
                pubkey3: PublicKey::from_secret_key(&secp, &sk).unwrap(),
            }
        }
    }

    #[test]
    fn ser_secp_primitives() {
        for _ in 0..10 {
            let s = SerTest::random();
            println!("Before Serialization: {:?}", s);
            let serialized = serde_json::to_string_pretty(&s).unwrap();
            println!("JSON: {}", serialized);
            let deserialized: SerTest = serde_json::from_str(&serialized).unwrap();
            println!("After Serialization: {:?}", deserialized);
            println!();
            assert_eq!(s, deserialized);
        }

        let secp = Secp256k1::with_caps(ContextFlag::Commit);
        let sk = SecretKey::new(&secp, &mut thread_rng());
        let mut msg = [0u8; 32];
        thread_rng().fill(&mut msg);
        let msg = Message::from_slice(&msg).unwrap();
        let sig = sign_single(&secp, &msg, &sk, None, None, None, None, None).unwrap();

        let serialized = serde_json::to_string_pretty(&sk).unwrap();
        println!("Serialized SecretKey: {}", serialized);
        let deserialized: SecretKey = serde_json::from_str(&serialized).unwrap();
        println!("Deserialized SecretKey: {:?}", deserialized);

        let serialized = serde_json::to_string_pretty(&sig).unwrap();
        println!("Serialized Signature: {}", serialized);
        let deserialized: Signature = serde_json::from_str(&serialized).unwrap();
        println!("Deserialized Signature: {:?}", deserialized);
    }
}