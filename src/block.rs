// Content-addressed binary block storage in separate files
// Warning: assumes it is the only program modifying the folder it is responsible for.
// Audit/improve this.

use futures::{sync::mpsc::{UnboundedReceiver, UnboundedSender,
                           unbounded as unbounded_channel},
              sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender,
                              channel as oneshot},
              Future,
              Stream};
use sha2::{Sha256, Digest};
use base64;
use lru_cache::LruCache;

use std::sync::Arc;
use std::thread;
use std::io::{self, Read, Write};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BlockHash(String);

pub type         BlockData = Arc<Vec<u8>>;
pub type  BlockGetResponse = OneshotReceiver<io::Result<BlockData>>;
pub type  BlockSetResponse = OneshotReceiver<io::Result<BlockHash>>;

type BlockGetResponder = OneshotSender<io::Result<BlockData>>;
type BlockSetResponder = OneshotSender<io::Result<BlockHash>>;

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
        self.0.unbounded_send(BlockRequest::Set(data, responder)).unwrap();
        response
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
        let BlockHash(ref string) = hash;
        let full_path = self.directory.join(Path::new(string));
        
        let mut file = fs::File::open(&full_path)?;
        let mut data = Vec::with_capacity(file.metadata()?.len() as usize);
        file.read_to_end(&mut data)?;
        
        let block_data = Arc::new(data);
        self.cache.borrow_mut().insert(hash, block_data);
        Ok(block_data)
    }

    fn set(&mut self, data: BlockData) -> io::Result<BlockHash>{
        // ensure directory exists
        fs::create_dir_all(&self.directory)?;
       
        // hash data
        let hash_binary = Sha256::digest(data.as_slice());
        let hash_string = base64::encode_config(hash_binary.as_slice(),
                          base64::URL_SAFE);
        // create file named after the sha256sum of its contents
        let full_path = self.directory.join(Path::new(&hash_string))?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            //.create_new(true)
            .open(&full_path);
        let mut file = match file{
            Ok(k) => k,
            Err(e) => /*
                if e.kind() == io::ErrorKind::AlreadyExists{
                    // if the file already exists, return the hash now, file on disk
                    // should already be valid.
                    // Commented this out because, not really. Files are not removed
                    // on write failure or power loss.
                    return Ok(BlockHash(hash_string))
                }
                else{ */
                    return Err(e)
                //}
        };
        
        file.write_all(data.as_slice())?;

        Ok(BlockHash(hash_string))
    }

    fn run(self, receiver: UnboundedReceiver<BlockRequest>){
        use self::BlockRequest::*;
        receiver.for_each(move |update|
            match update{
                Get(hash, responder) => {
                    if let Some(data) = self.cache.borrow_mut().get_mut(){
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
        ).wait();
    }
}
                
pub fn spawn_thread(directory: PathBuf) -> BlockStore{
    let (sender, receiver) = unbounded_channel();

    let thread = thread::spawn(move ||
        BlockStoreThread{
            directory,
            cache: LruCache::new(BLOCK_STORE_LRU_CAPACITY)
        }.run(receiver));

    BlockStore(sender)
}
