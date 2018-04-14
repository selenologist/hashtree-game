use futures::{sync::mpsc::{UnboundedReceiver, UnboundedSender,
                           unbounded as unbounded_channel},
              sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender,
                              channel as oneshot},
              future::IntoFuture,
              Future,
              Stream};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use serde::{de::DeserializeOwned, Serialize, Deserialize};
use serde_json::{to_vec as serialize, from_slice as deserialize};
use rpds::HashTrieSet;

use update::*;
use signed::*;
use block::*;

use std::sync::Arc;
use std::rc::Rc;
use std::cell::Cell;
use std::time::{UNIX_EPOCH, Duration, SystemTime, SystemTimeError};
use std::fmt::Debug;
use std::marker::PhantomData;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableTime(u64); // u64 seconds since unix epoch

impl SerializableTime{
    pub fn from_system(sys: SystemTime) -> Result<SerializableTime, SystemTimeError>{
        sys.duration_since(UNIX_EPOCH)
           .map(|sys_since_unix| SerializableTime(sys_since_unix.as_secs()))
    }
    pub fn from_system_now() -> Result<SerializableTime, SystemTimeError>{
        Self::from_system(SystemTime::now())
    }
    pub fn to_system(&self) -> SystemTime{
        use std::ops::Add;
        let &SerializableTime(secs_since_epoch) = self;
        UNIX_EPOCH.clone().add(Duration::from_secs(secs_since_epoch))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedData<'a, T: 'a + Debug + Serialize> where 'a: Deserialize<'a>{
    value: T,
    update: Option<Signed<'a, T>>, // None if root
    phantom: PhantomData<&'a T>
}

pub enum VerifierError{
    DisallowedKey,
    BadSignature,
    DecodeFailed,
    Stale,     // timestamp too old (replay protection)
    NotLatest, // newer last value exists
    LastErr,   // error retrieving last value
    UpdateErr, // error processing update
    StoreErr,  // error storing update
}

impl From<VerifyError> for VerifierError{
    fn from(v: VerifyError) -> Self{
        match v{
            VerifyError::DisallowedKey => VerifierError::DisallowedKey,
            VerifyError::BadSignature => VerifierError::BadSignature,
            VerifyError::DecodeFailed => VerifierError::DecodeFailed
        }
    }
}

pub type VerifierResult<T> = Result<BlockHash, VerifierError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Verifier<T:  Sized + Serialize + DeserializeOwned>{
    pub pubkey:  PublicKey,
    pub secret:  SecretKey,
    pub allowed: AllowedKeys,
    pub latest:  Rc<Cell<Option<BlockHash>>>,
    pub phantom: PhantomData<T>
}

impl<T: Serialize + DeserializeOwned + Debug> Verifier<T>{
    pub fn force(&self, store: &BlockStore, input: T) -> BlockHash{ // blocking, panicing
        let data = VerifiedData{
            value: input,
            update: None,
            phantom: PhantomData
        };
        let signeddata = Signed::sign(data, &self.pubkey, &self.secret).unwrap();
        let hash = store
            .set(Arc::new(serialize(&signeddata).unwrap()))
            .wait()
            .unwrap()
            .unwrap();

        hash
    }
    pub fn verify(&self, store: &BlockStore, input: Signed<T>)
        -> impl IntoFuture<Item=BlockHash, Error=VerifierError>
    {
        const STALE_SECONDS: u64 = 5; // if timestamp is more than this many seconds old, update is table

        let update: Update<T> = input
            .verify(&self.allowed)
            .map_err(|e| e.into())?;

        if let Some(latest) = self.latest.get(){
            if update.last != latest{
                return Err(VerifierError::NotLatest);
            }
        }
        
        let timestamp = update.timestamp.to_system();
        match SystemTime::now().duration_since(timestamp){
            Ok(duration) if duration.as_secs() < STALE_SECONDS => {}, // do nothing if not stale
            _ => {return Err(VerifierError::Stale);}
        }

        let latest = self.latest.clone(); // kept until end
        let last_block_future = store.get(update.last);
        last_block_future
            .then(|r| r.map_err(VerifierError::LastErr)) // Oneshot::Cancelled
            .map_err(|_| VerifierError::LastErr)  // io::Error
            .map(move |last_block| {
                let last_signed = deserialize(last_block.as_slice())
                    .map_err(|_| VerifierError::LastErr)?;

                // only the validator itself should be signing VerifiedData,
                // therefore only our key should be valid
                let allow_self = HashTrieSet::new().insert(self.pubkey.clone());
                let last: VerifiedData<T> = last_signed
                    .verify(&allow_self)
                    .map_err(|_| VerifierError::LastErr)?;

                let next = update.command
                    .process(last.value)
                    .map_err(|_| VerifierError::UpdateErr)?;

                let verified = VerifiedData{
                    value: next,
                    update: Some(update)
                };

                let signed_verified = Signed::sign(verified, &self.pubkey, &self.secret)
                    .map_err(|_| VerifierError::StoreErr)?;
                let signed_serialized = serialize(&signed_verified)
                    .map_err(|_| VerifierError::StoreErr)?;

                store.set(Arc::new(signed_serialized))
                     .then(|r|
                           r.map_err(VerifierError::StoreErr)) // Oneshot::Cancelled
                     .map_err(|_| VerifierError::StoreErr)  // io::Error
                     .map(move |hash| {
                         if let Some(latest) = latest.get(){
                             // check again incase a new latest made it through before this one
                             if update.last != latest{
                                 return Err(VerifierError::NotLatest);
                             }
                         }
                         latest.set(Some(hash.clone()));
                     
                         hash
                     })
            })
    }
}
