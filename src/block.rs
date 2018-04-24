// Content-addressed binary block storage in separate files
// Warning: assumes it is the only program modifying the folder it is responsible for.
// Audit/improve this.

use futures::{sync::mpsc::{UnboundedReceiver, UnboundedSender,
                           unbounded as unbounded_channel},
              sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender,
                              channel as oneshot},
              Stream};
use sha2::{Sha256, Digest};
use base64;
use lru_cache::LruCache;
use serde::{Deserialize, Deserializer, de::{self, Visitor}};

use std::sync::{Arc, RwLock};
use std::thread;
use std::io::{self, Read};
use std::fs;
use std::path::{Path, PathBuf};
use std::fmt::{self, Debug};
use std::collections::HashSet; // not to be confused with rpds::HashTrieSet
use std::str::FromStr;

struct StringInterner(RwLock<HashSet<Arc<String>>>); // Weak does not implement Hash

impl StringInterner{
    fn intern<T: Into<String>>(&self, s: T) -> Arc<String>{
        let s = s.into();
        { // try getting an already interned value using read part of a RwLock
            let r = self.0.read().unwrap();
            if let Some(interned) = r.get(&s){
                return interned.clone();
            }
        }
        { // warning: it is seemingly possible for a writer to write between our read and acquiring a write lock
            let mut w = self.0.write().unwrap();
            let a = Arc::new(s); // strong_count = 1
            w.insert(a.clone()); // strong_count = 2
            // purge any value in the set with a strong_count <= 1 (i.e. only referenced in the set)
            // XXX: do this less often, it's very inefficient
            trace!("{} interned strings", w.len());
            if w.len() > 256{ // crappy threshold for attempting to purge entries, this should be replaced with something that adjusts for how many typically remain
                w.retain(|e|{
                    trace!("{} references to {}", Arc::strong_count(e), e);
                    Arc::strong_count(e) > 1
                });
            }
            else{
                w.iter().for_each(|e| trace!("{} references to {}", Arc::strong_count(e), e));
            }
            return a;
        }
    }
}

lazy_static!{
    static ref GLOBAL_STRING_INTERNER: StringInterner =
        StringInterner(RwLock::new(HashSet::new()));
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct BlockHash(pub Arc<String>);

impl<'a> From<&'a str> for BlockHash{
    fn from(s: &'a str) -> BlockHash{
        BlockHash(GLOBAL_STRING_INTERNER.intern(s))
    }
}

struct BHVisitor;
impl<'de> Visitor<'de> for BHVisitor{
    type Value = BlockHash;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "a string")
    }

    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
        where E: de::Error
    {
        Ok(BlockHash::from(s))
    }
}

impl<'de> Deserialize<'de> for BlockHash{
    fn deserialize<D>(deserializer: D) -> Result<BlockHash, D::Error>
        where D: Deserializer<'de>
    {
        deserializer.deserialize_str(BHVisitor)
    }
}

pub type         BlockData = Arc<Vec<u8>>;
pub type  BlockGetResponse = OneshotReceiver<io::Result<BlockData>>;
pub type  BlockSetResponse = OneshotReceiver<io::Result<BlockHash>>;

type BlockGetResponder = OneshotSender<io::Result<BlockData>>;
type BlockSetResponder = OneshotSender<io::Result<BlockHash>>;

#[derive(Debug)]
enum BlockRequest{
    Get(BlockHash, BlockGetResponder),
    Set(BlockData, BlockSetResponder)
}

#[derive(Clone)]
pub struct BlockStore(UnboundedSender<BlockRequest>);

impl BlockStore{
    pub fn get(&self, hash: BlockHash) -> BlockGetResponse{
        let (responder, response) = oneshot();
        self.0.unbounded_send(BlockRequest::Get(hash, responder)).unwrap();
        response
    }
    pub fn set(&self, data: BlockData) -> BlockSetResponse{
        let (responder, response) = oneshot();
        match self.0.unbounded_send(BlockRequest::Set(data, responder)){
            Ok(_) => (),
            Err(e) => debug!("Failed to send Set to BlockStore, {:?}", e)
        }
        response
    }
}

impl Debug for BlockStore{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        write!(f, "BlockStore")
    }
}

// Number of chunks to cache in LRU.
// A chunk is expected to be not larger than 64K.
// So i.e. 256 chunks would be approx 16MB + hash space + pointers.
const BLOCK_STORE_LRU_CAPACITY: usize = 256;
struct BlockStoreThread{
    directory: PathBuf,
    cache: LruCache<BlockHash, BlockData>
}

impl BlockStoreThread{
    fn get(&mut self, hash: BlockHash) -> io::Result<BlockData>{
        let data = {
            let BlockHash(ref string) = hash;
            let full_path = self.directory.join(Path::new(string.as_ref()));
            
            let mut file = fs::File::open(&full_path)?;
            let mut data = Vec::with_capacity(file.metadata()?.len() as usize);
            file.read_to_end(&mut data)?;
            data
        };
            
        let block_data = Arc::new(data);
        self.cache.insert(hash, block_data.clone());
        Ok(block_data)
    }

    fn set(&mut self, data: BlockData) -> io::Result<BlockHash>{
        // ensure directory exists
        if let Err(e) = fs::create_dir_all(&self.directory){
            trace!("Failed to create dir {:?}", self.directory);
            return Err(e);
        }
       
        // hash data
        let hash_binary = Sha256::digest(data.as_slice());
        let hash_string = base64::encode_config(hash_binary.as_slice(),
                          base64::URL_SAFE_NO_PAD);
        // create file named after the sha256sum of its contents
        let full_path = self.directory.join(Path::new(&hash_string));
        ::write_then_rename(full_path,
                            |file| file.write_all(data.as_slice()))?;

        let block_hash = BlockHash(Arc::new(hash_string));
        self.cache.insert(block_hash.clone(), data);

        Ok(block_hash)
    }

    fn run(mut self, receiver: UnboundedReceiver<BlockRequest>){
        use self::BlockRequest::*;
        trace!("BlockStore thread running");
        receiver.map(move |update|{
            trace!("got {:?}", update);
            match update{
                Get(hash, responder) => {
                    if let Some(data) = self.cache.get_mut(&hash){
                        responder.send(Ok(data.clone())).unwrap();
                    }
                    else{
                        responder.send(self.get(hash)).unwrap();
                    }
                },
                Set(data, responder) => {
                    responder.send(self.set(data)).unwrap();
                }
            }
        }).wait().last();
        debug!("BlockStore thread exiting");
    }
}
                
pub fn spawn_thread(directory: PathBuf) -> BlockStore{
    let (sender, receiver) = unbounded_channel();

    let _thread = thread::Builder::new()
        .name("BlockStore".into())
        .spawn(move ||
        BlockStoreThread{
            directory,
            cache: LruCache::new(BLOCK_STORE_LRU_CAPACITY)
        }.run(receiver));

    BlockStore(sender)
}
