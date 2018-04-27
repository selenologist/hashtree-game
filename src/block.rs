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
use sled;

use std::sync::Arc;
use std::thread;
use std::io;
use std::path::{Path, PathBuf};
use std::fmt::{self, Debug};

const SHA256_BYTES: usize = 256 / 8;

// XXX intern these?
// YYY no don't, not yet, we don't create enough to make the interning table worth it. (Apr 27)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockHash(pub Arc<[u8; SHA256_BYTES]>);

impl<'a> From<&'a str> for BlockHash{
    fn from(s: &'a str) -> BlockHash{
        use base64::URL_SAFE_NO_PAD;
        let mut bytes: [u8; SHA256_BYTES];
        base64::decode_config_slice(&s, URL_SAFE_NO_PAD, &mut bytes)
            .unwrap();
        BlockHash(Arc::new(bytes))
    }
}

impl<'a> From<&'a [u8]> for BlockHash{
    fn from(s: &'a [u8]) -> BlockHash{
        let mut a: [u8; SHA256_BYTES];
        a.clone_from_slice(s);
        BlockHash(Arc::new(a))
    }
}

impl BlockHash{
    pub fn as_bytes<'a>(&'a self) -> &'a [u8]{
        &self.0[..]
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
// sled probably does caching of its own, but this should keep the block in
// an Arc and thus serve as in-memory deduplication.
const BLOCK_STORE_LRU_CAPACITY: usize = 256;
struct BlockStoreThread{
    store: sled::Tree,
    cache: LruCache<BlockHash, BlockData>
}

impl BlockStoreThread{
    fn get(&mut self, hash: BlockHash) -> io::Result<BlockData>{
        // cache is tried before this function is called
        
        use sled::Error::*;
        let data = self.store.get(hash.as_bytes())
            .map_err(|e| match e{
                Io(ie) => ie,
                CasFailed(_) =>
                    io::Error::new(io::ErrorKind::Interrupted, e),
                Unsupported(_) =>
                    io::Error::new(io::ErrorKind::InvalidInput, e),
                ReportableBug(s) =>
                    io::Error::new(io::ErrorKind::Other, s),
                Corruption{at} =>
                    io::Error::new(io::ErrorKind::InvalidData,
                                   format!("Corruption at {}", at))
            })
            .and_then(|r|
                      r.ok_or_else(|| io::Error::new(io::ErrorKind::NotFound,
                                                     "BlockHash not found")))?;
        let block_data = Arc::new(data);
        self.cache.insert(hash, block_data.clone());
        Ok(block_data)
    }

    fn set(&mut self, data: BlockData) -> io::Result<BlockHash>{
        // hash data
        let hash_digest = Sha256::digest(data.as_slice());
        let hash = BlockHash::from(&hash_digest[..]);

        // why on earth does sled need to own a vec ಠ_ಠ
        let key = hash.as_bytes().to_vec();
        let value = (*data).clone();
        self.store.set(key, value);

        self.cache.insert(hash.clone(), data);

        Ok(hash)
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
                
pub fn spawn_thread<P: AsRef<Path>>(path: P) -> BlockStore{
    let (sender, receiver) = unbounded_channel();
    let path: PathBuf = path.as_ref().to_path_buf(); // need to own to move into new thread

    let _thread = thread::Builder::new()
        .name("BlockStore".into())
        .spawn(move ||{
            let store =
                sled::Tree::start(sled::ConfigBuilder::new().path(path).build())
                .unwrap_or_else(|e| panic!("failed to open sled {:?}", path.as_path()));
            BlockStoreThread{
                store,
                cache: LruCache::new(BLOCK_STORE_LRU_CAPACITY)
            }.run(receiver)
        });

    BlockStore(sender)
}

pub mod base64_blockhash{
    use serde::{Deserialize, Serializer, Deserializer};
    use base64::{self, URL_SAFE_NO_PAD};
    use super::{SHA256_BYTES, BlockHash};
    pub fn serialize<S>(t: &BlockHash, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let s = base64::encode_config(t.0.as_ref(), URL_SAFE_NO_PAD);
        serializer.serialize_str(&s)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<BlockHash, D::Error>
        where D: Deserializer<'de>
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let mut bytes: [u8; SHA256_BYTES];
        base64::decode_config_slice(&s, URL_SAFE_NO_PAD, &mut bytes)
            .map_err(|e| Error::custom(e.to_string()))?;
        Ok(BlockHash::from(&bytes[..]))
    }
}

