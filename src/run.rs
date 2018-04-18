use sodiumoxide::crypto::sign::ed25519::{gen_keypair};
use futures::{IntoFuture, Future};

use std::path::{PathBuf};

use verify::*;
use update::*;
use signed::*;
use block::{self, *};
use http;
use websocket;

pub fn main(){
    const BLOCKS_DIR: &'static str = "public/blocks/";
    const ROOTKEY_FILE: &'static str = "secret/root_key";

    //    let (pubsub, _) = router::PubSub::spawn_thread();
    http::spawn_thread();
    let block_store = block::spawn_thread(PathBuf::from(BLOCKS_DIR));
    let root = match KeyPair::from_file(ROOTKEY_FILE){
        Ok(rk) => rk,
        Err(e) => {
            info!("Failed to load root keypair ({}), creating new one", e);
            let (pubkey, secret) = gen_keypair();
            let root = KeyPair{
                pubkey,
                secret
            };
            root.to_file(ROOTKEY_FILE).unwrap();
            root
        }
    };
    let verifier = match Verifier::from_file("secret/test_verifier"){
        Ok(v) => v,
        Err(e) => {
            info!("Failed to load verifier ({}), creating new one", e);
            let mut v = Verifier::default();
            v.add_allowed(root.pubkey.clone());
            info!("New verifier latest {:?}", v.force(&block_store, TestObject::default()));
            v
        }
    };
    /*verifier.add_allowed(root.pubkey.clone());
    let command = TestCommand::Add(3);
    let update = command.into_update(verifier.latest.borrow().clone().unwrap());
    let signedupdate = Signed::sign(update, &root.pubkey, &root.secret).unwrap();
    //println!("signedupdate {}", serde_json::to_string_pretty(&signedupdate).unwrap());
    let after: Result<BlockHash, VerifierError> = verifier.verify::<TestObject, TestCommand>(&block_store, signedupdate).into_future().wait();
    info!("latest after update {:?}", after);
    verifier.to_file("secret/test_verifier").unwrap();*/

    websocket::spawn_thread(block_store.clone()).join();
}
