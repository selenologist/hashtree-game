use serde::{Serialize, de::DeserializeOwned};
use serde_json::{to_writer as serialize_file, from_reader as deserialize_file};
use rmp_serde::{to_vec as serialize, from_slice as deserialize};
use sodiumoxide::crypto::sign::ed25519::{sign as crypto_sign, verify as crypto_verify, gen_keypair};
use rpds::HashTrieSet;

use std::io;
use std::fs;
use std::path::Path;

pub use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct Signed{
    #[serde(with="base64_public")]
    pub user: PublicKey,
    data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum VerifyError{
    DisallowedKey,
    BadSignature,
    DecodeFailed
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SignError{
    EncodeFailed
}

pub type AllowedKeys = HashTrieSet<PublicKey>;

pub type SignResult      = Result<Signed, SignError>;
pub type VerifyResult<T> = Result<T, VerifyError>;
impl Signed{
    pub fn sign<T: Serialize>(t: T, keypair: &KeyPair) -> SignResult
    {
        let serialized = serialize(&t)
            .map_err(|_| SignError::EncodeFailed)?;
        let signed = crypto_sign(&serialized[..], &keypair.secret);
        Ok(Signed{
            user: keypair.public.clone(),
            data: signed,
        })
    }

    pub fn verify<T: DeserializeOwned>(&self, allowed: &AllowedKeys) -> VerifyResult<T>{
        if !allowed.contains(&self.user){
            return Err(VerifyError::DisallowedKey);
        }

        let data =
            crypto_verify(&self.data[..], &self.user)
                .map_err(|_| VerifyError::BadSignature)?;
        let result = deserialize::<T>(&data[..]).map_err(|e|{
            error!("Failed to decode: {:?}", e);
            VerifyError::DecodeFailed
        })?;

        Ok(result)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyPair{
    #[serde(with="base64_public")]
    pub public: PublicKey,
    #[serde(with="base64_secret")]
    pub secret: SecretKey
}

impl KeyPair{
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<KeyPair>{
        use std::io::{Error, ErrorKind};
        deserialize_file(fs::File::open(path)?).map_err(|e| match e {
            _ => Error::new(ErrorKind::InvalidData, e)
        })
    }
    pub fn from_file_or_new<P: AsRef<Path> + Clone>(path: P) -> KeyPair{
        Self::from_file(path.clone())
            .unwrap_or_else(move |e|{
                error!("Failed to open keypair file {:?} ({:?}), creating new keypair",
                      path.as_ref(), e);
                let kp = KeyPair::generate();
                kp.to_file(path).unwrap();
                kp
            })
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()>{
        use std::io::{Error, ErrorKind};
        ::write_then_rename(
            path,
            |writer| serialize_file(writer, &self)
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e)))
    }

    
    pub fn generate() -> KeyPair{
        let (public, secret) = gen_keypair();
        KeyPair{ public, secret }
    }
}

pub mod base64_public{
    use serde::{Deserialize, Serializer, Deserializer};
    use base64::{self, URL_SAFE_NO_PAD};
    use super::PublicKey;
    pub fn serialize<S>(t: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let s = base64::encode_config(t.as_ref(), URL_SAFE_NO_PAD);
        serializer.serialize_str(&s)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
        where D: Deserializer<'de>
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes = base64::decode_config(&s, URL_SAFE_NO_PAD)
            .map_err(|e| Error::custom(e.to_string()))?;
        let key = PublicKey::from_slice(&bytes[..])
            .ok_or_else(|| Error::custom("Failed to decode PublicKey"));
        key
    }
}
pub mod base64_secret{
    use serde::{Deserialize, Serializer, Deserializer};
    use base64::{self, URL_SAFE_NO_PAD};
    use super::SecretKey;
    pub fn serialize<S>(t: &SecretKey, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let &SecretKey(ref slice) = t;
        let s = base64::encode_config(&slice[..], URL_SAFE_NO_PAD);
        serializer.serialize_str(&s)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<SecretKey, D::Error>
        where D: Deserializer<'de>
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes = base64::decode_config(&s, URL_SAFE_NO_PAD)
            .map_err(|e| Error::custom(e.to_string()))?;
        let key = SecretKey::from_slice(&bytes[..])
            .ok_or_else(|| Error::custom("Failed to decode SecretKey"));
        key
    }
}
