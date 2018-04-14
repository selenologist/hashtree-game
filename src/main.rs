#![feature(test)]
#![feature(conservative_impl_trait)]

extern crate test;

extern crate futures;
extern crate tokio_core;

extern crate sha2;

extern crate base64;

extern crate lodepng;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate rpds;
extern crate lru_cache;

extern crate sodiumoxide;

//mod router;
mod block;
mod signed;
mod verify;
mod update;

use futures::{Future};

use std::sync::Arc;
use std::path::PathBuf;

fn main() {
    use sodiumoxide::crypto::sign::ed25519::{sign, verify, gen_keypair, PublicKey, SecretKey};
    use serde_json::{to_vec as serialize, from_slice as deserialize};
    use verify::*;
    use update::*;
    use signed::*;
    use rpds::HashTrieSet;
    use std::rc::Rc;
    use std::cell::Cell;
    
    env_logger::init();
//    let (pubsub, _) = router::PubSub::spawn_thread();
    let block_store = block::spawn_thread(PathBuf::from("public/"));
    let (user_pk, user_sk) = gen_keypair();
    let (verifier_pk, verifier_sk) = gen_keypair();
    let verifier = Verifier{
        pubkey: verifier_pk.clone(),
        secret: verifier_sk,
        allowed: HashTrieSet::new().insert(user_pk.clone()),
        latest: Rc::new(Cell::new(None))
    };
    let initial = verifier.force(TestObject::default());
    println!("initial {:?}", initial);
    let command = TestCommand::Add(3);
    let update = command.into_update(initial);
    println!("update {}", serde_json::to_string_pretty(&update));
    let signedupdate = Signed::sign(update, user_pk, user_sk).unwrap();
    println!("signedupdate {}", serde_json::to_string_pretty(&signedupdate));
    let after = verifier.verify(&block_store, signedupdate).wait();
    println!("after {:?}", after);

    //let _ = websocket::WebsocketThread::spawn(pubsub);
}

#[cfg(test)]
mod tests{
    use super::*;
    use test::Bencher;
    use futures::Stream;

    #[test]
    fn pubsub(){
        use tokio_core::reactor::Core;
        use router::*;
        use std::thread;

        let (pubsub, _) = PubSub::spawn_thread();
        let mk_thread = |ps: PubSubHandle<String>|{
            thread::spawn(
                move ||{
                let mut core = Core::new().unwrap();
                let timeout = tokio_core::reactor::Timeout::new(
                    std::time::Duration::from_secs(3),
                    &core.handle()).unwrap();
                let fut = timeout.map_err(|_| ()).select(ps
                    .attach("Test".into())
                    .map_err(|_|()).and_then({
                    |topic|
                    topic.receiver.for_each(move |msgs|{
                        println!("Thread {:?} got {}", thread::current().id(), msgs);
                        Ok(())
                    })
                }));
                core.run(fut);
                println!("Thread {:?} exiting", thread::current().id());
            })};

        let a = mk_thread(pubsub.clone());
        let b = mk_thread(pubsub.clone());
       
        let topic = pubsub
            .attach("Test".to_string())
            .and_then(|topic| Ok(topic)).wait().unwrap();

        let c = mk_thread(pubsub.clone());

        topic.send(Arc::new("test!".into()));
        
        pubsub.send("Test".to_string(), Arc::new("test test test".into()));

        a.join();
        b.join();
        c.join();
    }

    #[test]
    fn cas(){
        let (cas, _) = cas::CasThread::spawn_thread("test_directory".into());
        let (hash, sync) = cas.store(Arc::new(String::from("Hello World").into_bytes()), true);
        hash.and_then(move |h|{
            println!("\"Hello World\" hashed into {}", h);
            sync.unwrap()
        }).and_then(move |res| {
            println!("IO result: {:?}", res);
            cas.load(String::from("SGVsbG8gV29ybGQ="))
        }).map(|l| println!("Load result: {:?}", l)).wait();
    }

    #[test]
    fn cache_cas(){
        let (cas, _) = cas::CasThread::spawn_thread("test_directory".into());
        let mut cas = cas::CasCachedHandle::new(cas);
        cas.store(Arc::new(String::from("World Hello").into_bytes()), true)
           .and_then(move |(hash, result)|{
               println!("\"World Hello\" hashed to {} and stored with result {:?}",
                        hash, result);
               cas.load(String::from("V29ybGQgSGVsbG8="))
        }).map(|l| println!("Load result: {:?}", l)).wait();
    }
}

