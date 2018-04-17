use serde::{Serialize, de::DeserializeOwned};
use rmp_serde::{to_vec as serialize, from_slice as deserialize};
use sodiumoxide::crypto::sign::ed25519::{sign as crypto_sign, verify as crypto_verify, PublicKey, SecretKey};
use rpds::HashTrieSet;

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
