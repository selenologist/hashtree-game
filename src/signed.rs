use futures::{Future,
              Stream};

use serde::{de::DeserializeOwned, Serialize, Deserialize};
use serde_json::{to_vec as serialize, from_slice as deserialize};
use sodiumoxide::crypto::sign::ed25519::{sign, verify, PublicKey, SecretKey};
use rpds::HashTrieSet;

use std::marker::PhantomData;
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub struct Signed<'a, T: 'a + Serialize + Deserialize<'a>>{
    user: PublicKey,
    data: Vec<u8>,
    phantom: PhantomData<&'a T>
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

pub type SignResult<'a, T> = Result<Signed<'a, T>, SignError>;
pub type VerifyResult<T> = Result<T, VerifyError>;
impl<'a, T: Serialize + Deserialize<'a>> Signed<'a, T>{
    pub fn sign(t: T, user_pk: &PublicKey, user_sk: &SecretKey)
        -> SignResult<'a, T>
    {
        let serialized = serialize(&t)
            .map_err(|_| SignError::EncodeFailed)?;
        let signed = sign(&serialized[..], user_sk);
        Ok(Signed{
            user: user_pk.clone(),
            data: signed,
            phantom: PhantomData
        })
    }

    pub fn verify(&self, allowed: &AllowedKeys) -> VerifyResult<T>{
        if !allowed.contains(&self.user){
            return Err(VerifyError::DisallowedKey);
        }

        verify(&self.data[..], &self.user)
            .map_err(|_| VerifyError::BadSignature)
            .map(|data| deserialize(&data[..]).map_err(|_| VerifyError::DecodeFailed))
    }
}
