use sodiumoxide::crypto::sign::ed25519::{gen_keypair};
use rpds::HashTrieSet;
use futures::{IntoFuture, Future};

use std::rc::Rc;
use std::cell::RefCell;
use std::path::PathBuf;

use verify::*;
use update::*;
use signed::*;
use block::{self, *}; 

pub fn main(){
    //    let (pubsub, _) = router::PubSub::spawn_thread();
    let block_store = block::spawn_thread(PathBuf::from("public/blocks/"));
    let (user_pk, user_sk) = gen_keypair();
    let mut verifier = match Verifier::from_file("secret/test_verifier"){
        Ok(v) => v,
        Err(e) => {
            info!("Failed to load verifier ({}), creating new one", e);
            let (verifier_pk, verifier_sk) = gen_keypair();
            let v = Verifier{
                pubkey: verifier_pk.clone(),
                secret: verifier_sk,
                allowed: HashTrieSet::new(),
                latest: Rc::new(RefCell::new(None)),
            };
            info!("New verifier latest {:?}", v.force(&block_store, TestObject::default()));
            v
        }
    };
    verifier.add_allowed(user_pk.clone());
    let command = TestCommand::Add(3);
    let update = command.into_update(verifier.latest.borrow().clone().unwrap());
    let signedupdate = Signed::sign(update, &user_pk, &user_sk).unwrap();
    //println!("signedupdate {}", serde_json::to_string_pretty(&signedupdate).unwrap());
    let after: Result<BlockHash, VerifierError> = verifier.verify::<TestObject, TestCommand>(&block_store, signedupdate).into_future().wait();
    info!("latest after update {:?}", after);
    verifier.to_file("secret/test_verifier").unwrap();

    //let _ = websocket::WebsocketThread::spawn(pubsub);
}
