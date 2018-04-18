use serde::{Serialize, de::DeserializeOwned};
use serde_json::{to_writer as serialize_file, from_reader as deserialize_file};
use rmp_serde::{to_vec as serialize, from_slice as deserialize};
use sodiumoxide::crypto::sign::ed25519::{sign as crypto_sign, verify as crypto_verify, gen_keypair, PublicKey, SecretKey};
use rpds::HashTrieSet;

use std::io;
use std::fs;
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct Signed{
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
    pub fn sign<T: Serialize>(t: T, user_pk: &PublicKey, user_sk: &SecretKey) -> SignResult
    {
        let serialized = serialize(&t)
            .map_err(|_| SignError::EncodeFailed)?;
        let signed = crypto_sign(&serialized[..], user_sk);
        Ok(Signed{
            user: user_pk.clone(),
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
        let result = deserialize::<T>(&data[..]).map_err(|_| VerifyError::DecodeFailed)?;

        Ok(result)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyPair{
    #[serde(with="base64_url_safe_no_pad_pub")]
    pub pubkey: PublicKey,
    #[serde(with="base64_url_safe_no_pad_sec")]
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
                info!("Failed to open keypair file {:?} ({:?}), creating new keypair",
                      path.as_ref(), e);
                let (pubkey, secret) = gen_keypair();
                let kp = KeyPair{
                    pubkey, secret
                };
                kp.to_file(path).unwrap();
                kp
            })
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()>{
        use std::io::{Error, ErrorKind};
        serialize_file(&mut fs::File::create(path)?, &self).map_err(|e| match e{
            _ => Error::new(ErrorKind::InvalidInput, e)
        })
    }
}

pub mod base64_url_safe_no_pad_pub{
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
pub mod base64_url_safe_no_pad_sec{
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
