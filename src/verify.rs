use futures::{Future, future::IntoFuture};
use sodiumoxide::crypto::sign::ed25519::{PublicKey, SecretKey};
use serde::{Serialize, Deserialize};
use rmp_serde::{to_vec as serialize, from_slice as deserialize};
use serde_json::{to_writer as serialize_file, from_reader as deserialize_file};
use rpds::HashTrieSet;

use update::*;
use signed::*;
use block::*;

use std::sync::Arc;
use std::rc::Rc;
use std::cell::RefCell;
use std::time::{UNIX_EPOCH, Duration, SystemTime, SystemTimeError};
use std::fmt::Debug;
use std::io;
use std::fs;
use std::path::Path;

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
    pub fn to_u64(&self) -> u64{
        let &SerializableTime(u) = self;
        u
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedData<T: Debug + Serialize>{
    pub value: T,
    pub update: Option<Signed>, // None if root
}

#[derive(Debug, Copy, Clone)]
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

//pub type VerifierResult = Result<BlockHash, VerifierError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Verifier{
    pub pubkey:  PublicKey,
    pub secret:  SecretKey,
    pub allowed: AllowedKeys,
    pub latest:  Rc<RefCell<Option<BlockHash>>>,
}

impl Verifier{
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Verifier>{
        //use rmp_serde::decode::Error::*;
        deserialize_file(fs::File::open(path)?).map_err(|e| match e {
            /*
            InvalidMarkerRead(e) |
            InvalidDataRead(e)   => e,
            */
            _ => io::Error::new(io::ErrorKind::InvalidData, e)
        })
    }
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()>{
        /*use rmp_serde::encode::Error::*;
        use rmp::encode::ValueWriteError;*/
        serialize_file(&mut fs::File::create(path)?, &self).map_err(|e| match e{
            /*
            InvalidValueWrite(ValueWriteError::InvalidMarkerWrite(e)) => e,
            InvalidValueWrite(ValueWriteError::InvalidDataWrite(e)) => e,
            */
            _ => io::Error::new(io::ErrorKind::InvalidInput, e)
        })
    }
    pub fn add_allowed(&mut self, key: PublicKey){
        self.allowed.insert_mut(key);
    }
    pub fn force<T: Serialize + Debug>(&self, store: &BlockStore, input: T) -> BlockHash{ // blocking, panicing, replaces latest
        let data = VerifiedData{
            value: input,
            update: None,
        };
        let signeddata = Signed::sign(data, &self.pubkey, &self.secret).unwrap();
        let hash_result = store
            .set(Arc::new(serialize(&signeddata).unwrap()))
            .wait();
        trace!("force result {:?}", hash_result);

        let hash = hash_result.unwrap().unwrap();
        *self.latest.borrow_mut() = Some(hash.clone());

        hash
    }
    pub fn verify<T: Serialize + Debug, U: Command<T>>(&self, store: &BlockStore, input: Signed)
        -> impl IntoFuture<Item=BlockHash, Error=VerifierError>
        where for <'de> U: Deserialize<'de>,
              for <'de> T: Deserialize<'de>
    {
        const STALE_SECONDS: u64 = 5; // if timestamp is more than this many seconds old, update is stale

        let update: Update<U> = input
            .verify(&self.allowed)
            .map_err(|e| -> VerifierError {e.into()})?;

        {
            if let Some(ref latest) = *self.latest.borrow(){
                if update.last != *latest{
                    return Err(VerifierError::NotLatest);
                }
            }
        }
        
        let timestamp = update.timestamp.to_system();
        match SystemTime::now().duration_since(timestamp){
            Ok(duration) if duration.as_secs() < STALE_SECONDS => {}, // do nothing if not stale
            _ => {return Err(VerifierError::Stale);}
        }

        let latest = self.latest.clone(); // kept until end
        let command = update.command;
        let last = update.last;
        let last_block_future = store.get(last.clone());
        let sign_future = last_block_future
            .map_err(|_| VerifierError::LastErr) // Oneshot::Cancelled
            .and_then(move |last_block| -> Result<Arc<Vec<u8>>, VerifierError> {
                let last_block = last_block.map_err(|_| VerifierError::LastErr)?; // io::Error
                let last_signed: Signed = deserialize(last_block.as_slice())
                    .map_err(|_| VerifierError::LastErr)?;

                // only the validator itself should be signing VerifiedData,
                // therefore only our key should be valid
                let allow_self = HashTrieSet::new().insert(self.pubkey.clone());
                let last: VerifiedData<_> = last_signed
                    .verify(&allow_self)
                    .map_err(|_| VerifierError::LastErr)?;

                let next:_ = command
                    .process(last.value)
                    .map_err(|_| VerifierError::UpdateErr)?;

                let verified = VerifiedData{
                    value: next,
                    update: Some(input)
                };

                let signed_verified = Signed::sign(verified, &self.pubkey, &self.secret)
                    .map_err(|_| VerifierError::StoreErr)?;
                let signed_serialized = serialize(&signed_verified)
                    .map_err(|_| VerifierError::StoreErr)?;

                Ok(Arc::new(signed_serialized))
            });
        sign_future
            .map(|data: Arc<Vec<u8>>| store.set(data))
            .and_then(|recv: _| recv
                .then(|hash: Result<io::Result<BlockHash>, _>| {
                    let hash = if let Ok(Ok(hash)) = hash { hash } else{ return Err(VerifierError::StoreErr) };
                    // check again incase a new latest made it through before this one
                    if Some(last) != *latest.borrow(){
                        return Err(VerifierError::NotLatest);
                    }
                    latest.replace(Some(hash.clone()));
                
                    Ok(hash)
                })
               .map_err(|_| VerifierError::StoreErr)
            ).wait()
    }
}
