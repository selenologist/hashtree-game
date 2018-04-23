use futures::{Future, future, future::IntoFuture};
use sodiumoxide::crypto::sign::ed25519::{PublicKey};
use serde::{Serialize, Deserialize};
use rmp_serde::{to_vec_named as serialize, from_slice as deserialize};
use serde_json::{to_writer as serialize_readable_file, from_reader as deserialize_readable_file};
use rpds::{HashTrieSet, HashTrieMap};

use update::{Update, Command};
use signed::{Signed, VerifyError, AllowedKeys, KeyPair};
use block::{BlockHash, BlockStore};
use ltime::{now_check_stale};

use std::sync::Arc;
use std::rc::Rc;
use std::cell::RefCell;
use std::fmt::Debug;
use std::io;
use std::fs;
use std::path::{Path, PathBuf};
//use std::marker::PhantomData;

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifiedData<T: Debug + Serialize>{
    pub value: T,
    pub update: Option<Signed>, // None if root
}

#[derive(Debug, Copy, Clone, Serialize)]
#[serde(tag="Error")]
pub enum VerifierError{
    DisallowedKey,
    BadSignature,
    DecodeFailed,
    Stale,      // timestamp too old (replay protection)
    NotLatest,  // newer last value exists
    LastErr,    // error retrieving last value
    UpdateErr,  // error processing update
    StoreErr,   // error storing update
    NoVerifier, // used by VerifierMap to indicate there was no verifier by the given name
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
    #[serde(flatten)]
    pub keypair: KeyPair,
    pub allowed: AllowedKeys,
    pub latest:  Rc<RefCell<Option<BlockHash>>>,
}

impl Verifier{
    pub fn from_file<P: AsRef<Path>>(path: P) -> io::Result<Verifier>{
        Self::from_reader(fs::File::open(path)?)
    }
    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> io::Result<()>{
        self.to_writer(&mut fs::File::create(path)?)
    }
    
    pub fn from_reader<R: io::Read>(rdr: R) -> io::Result<Verifier>{
        deserialize_readable_file(rdr).map_err(|e| match e {
            _ => io::Error::new(io::ErrorKind::InvalidData, e)
        })
    }
    pub fn to_writer<W: io::Write>(&self, wtr: W) -> io::Result<()>{
        serialize_readable_file(wtr, &self).map_err(|e| match e{
            /*
            InvalidValueWrite(ValueWriteError::InvalidMarkerWrite(e)) => e,
            InvalidValueWrite(ValueWriteError::InvalidDataWrite(e)) => e,
            */
            _ => io::Error::new(io::ErrorKind::InvalidInput, e)
        })
    }


    pub fn new(with_keypair: Option<KeyPair>, with_allowed: Option<AllowedKeys>,
               with_latest: Option<BlockHash>)
        -> Verifier
    {
        let keypair = 
            if let Some(keypair) = with_keypair{
                keypair
            }
            else{
                KeyPair::generate()
            };
        let allowed =
            if let Some(allowed) = with_allowed{
                allowed
            }
            else{
                HashTrieSet::new()
            };

        Verifier{
            keypair, allowed,
            latest: Rc::new(RefCell::new(with_latest))
        }
    }


    pub fn add_allowed(&mut self, key: PublicKey){
        self.allowed.insert_mut(key);
    }

    pub fn force<T: Serialize + Debug>(&self, store: &BlockStore, input: T) -> BlockHash{ // blocking, panicing, replaces latest
        let hash_result = store_verified(store, input, &self.keypair);
        trace!("force result {:?}", hash_result);

        let hash = hash_result.unwrap();
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
        if now_check_stale(timestamp, STALE_SECONDS){
            return Err(VerifierError::Stale);
        }

        let latest = self.latest.clone(); // kept until end
        let command = update.command;
        let last = update.last;
        let last_block_future = store.get(last.clone())
            .map_err(|_| VerifierError::LastErr); // Oneshot::Cancelled
        let sign_future = last_block_future
            .and_then(move |last_block| -> Result<Arc<Vec<u8>>, VerifierError> {
                let last_block = last_block.map_err(|_| VerifierError::LastErr)?; // io::Error
                let last_signed: Signed = deserialize(last_block.as_slice())
                    .map_err(|_| VerifierError::LastErr)?;

                // only the validator itself should be signing VerifiedData,
                // therefore only our key should be valid
                let allow_self = HashTrieSet::new()
                    .insert(self.keypair.public.clone());

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

                let signed_verified = Signed::sign(verified, &self.keypair)
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

impl Default for Verifier{
    fn default() -> Self{
        Verifier{
            keypair: KeyPair::generate(),
            allowed: HashTrieSet::new(),
            latest: Rc::new(RefCell::new(None)),
        }
    }
}

// not to be confused with a Map Verifier, this maps string keys to verifiers of a certain type
pub struct VerifierMap{
    dir:       PathBuf,
    verifiers: HashTrieMap<String, Verifier> // I don't actually have a good reason for using rpds here
}

impl VerifierMap{
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> io::Result<VerifierMap>{
        use std::ffi::OsStr;

        let mut verifiers = HashTrieMap::new();
        for rentry in fs::read_dir(dir.as_ref())?{
            let entry = rentry?;
            let path  = entry.path();
            if entry.file_type()?.is_file(){
                let v = Verifier::from_file(&path)?;
                let name = path
                    .file_name()
                    .and_then(|o: &OsStr| o.to_str())
                    .and_then(|s: &str| Some(String::from(s)))
                    .ok_or_else(
                        || io::Error::new(io::ErrorKind::InvalidInput, 
                                          format!("Error converting path {:?} to String while loading Verifiers from {:?}",
                                                  path, dir.as_ref())))?;
                trace!("Loaded verifier {}/{}", dir.as_ref().display(), name);
                verifiers.insert_mut(name, v);
            }
        }
        if verifiers.size() == 0{
            return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("VerifierMap directory {:?} exists but contains no Verifiers", dir.as_ref())));
        }

        Ok(VerifierMap{
            dir: ::absolute_pathbuf(dir),
            verifiers
        })
    }
    pub fn to_new_dir<P: AsRef<Path>>(&self, dir: P) -> io::Result<()>{
        // ensure dir exists
        fs::create_dir_all(dir.as_ref())?;

        for (name, verifier) in self.verifiers.iter(){
            let path = dir.as_ref().join(name);
            ::write_then_rename(path, move |wtr| verifier.to_writer(wtr))?;
            trace!("Wrote verifier {}/{}", dir.as_ref().display(), name);
        }

        Ok(())
    }
    pub fn to_dir(&self) -> io::Result<()>{
        self.to_new_dir(&self.dir)
    }


    pub fn add_new(&mut self, key: String,
                   with_keypair: Option<KeyPair>,
                   with_allowed: Option<AllowedKeys>,
                   with_latest:  Option<BlockHash>)
        -> io::Result<()>
    {
        if self.verifiers.contains_key(&key){
            debug!("Tried to add new verifier {} when one already exists!", key);
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,
                                      format!("Verifier {} already exists", key)));
        }
        let v = Verifier::new(with_keypair, with_allowed, with_latest);
        self.verifiers.insert_mut(key, v);

        Ok(())
    }

    pub fn new<P: AsRef<Path>>(dir: P) -> VerifierMap{
        VerifierMap{
            dir: ::absolute_pathbuf(dir),
            verifiers: HashTrieMap::default()
        }
    }

    pub fn verify<T: Serialize + Debug, U: Command<T>>(&self, store: &BlockStore, input: Signed, key: &String)
        -> impl Future<Item=BlockHash, Error=VerifierError>
        where for <'de> U: Deserialize<'de>,
              for <'de> T: Deserialize<'de>
    {
        use ::futures::future::Either; // later versions rename A and B, unfortunately
        if let Some(value) = self.verifiers.get(key){
            Either::A(value.verify::<T, U>(store, input).into_future())
        }
        else{
            Either::B(future::err(VerifierError::NoVerifier))
        }
    }
    pub fn latest(&self, key: &String) -> Option<BlockHash>{
        if let Some(value) = self.verifiers.get(key){
            value.latest.borrow().clone()
        }
        else{
            None
        }
    }
}

// blocking, panicing
pub fn store_verified<T: Serialize + Debug>(store: &BlockStore, input: T, keypair: &KeyPair)
    -> io::Result<BlockHash>
{
    let data = VerifiedData{
        value: input,
        update: None,
    };
    Signed::sign(data, keypair)
        .map_err(|_| io::Error::new(io::ErrorKind::Other,
                                    "Failed to sign data for storage"))
        .and_then(
            |signed_data|
            store
                .set(Arc::new(serialize(&signed_data).unwrap()))
                .wait()
                .unwrap())
}

