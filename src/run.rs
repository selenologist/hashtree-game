use std::path::{PathBuf};

use signed::{KeyPair};
use block::{self};
use http;
use websocket;
use map;
use router;
use rebuilder;
use reloader;

pub fn main(){
    const BLOCKS_DIR: &'static str = "public/blocks/";
    const ROOTKEY_FILE: &'static str = "secret/root_key";

    // quickfix: make sure secret/ exists
    ::std::fs::create_dir_all("secret/").unwrap();

    let pubsub  = router::PubSub::spawn_thread();
    
    rebuilder::spawn_thread(pubsub.clone());
    
    http::spawn_thread();
    
    let block_store = block::spawn_thread(PathBuf::from(BLOCKS_DIR));
    
    let root = match KeyPair::from_file(ROOTKEY_FILE){
        Ok(rk) => rk,
        Err(e) => {
            error!("Failed to load root keypair ({}), creating new one", e);
            let root = KeyPair::generate();
            root.to_file(ROOTKEY_FILE).unwrap();
            root
        }
    };

    let map_thread =
        map::spawn_thread(block_store.clone(),
                          root.public.clone());
    
    reloader::spawn_thread(pubsub);

    websocket::spawn_thread(block_store, map_thread).join().unwrap();
}
