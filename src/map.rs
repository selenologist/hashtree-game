use sodiumoxide::crypto::sign::ed25519::{PublicKey};
use rpds::{HashTrieSet, HashTrieMap};
use tokio_core::{self};//, reactor::Handle};
use futures::{sync::{mpsc::{UnboundedReceiver, UnboundedSender,
                            unbounded as unbounded_channel},
                     oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender,
                               Canceled as OneshotCanceled,
                               channel as oneshot}},
              Future,
              Stream};
use serde::{Serialize, Deserialize};

use std::thread;

use verify::{Verifier, VerifierMap, VerifierError, store_verified};
use signed::{Signed, KeyPair};
use block::{BlockStore, BlockHash};
use update::{Command, NamedHash, NamedHashCommand};

type MapThreadSender   = UnboundedSender<(Request, Responder)>;
type MapThreadReceiver = UnboundedReceiver<(Request, Responder)>;
type Responder = OneshotSender<MapResponse>;
type Response = OneshotReceiver<MapResponse>;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="Req")]
pub enum VerifierRequest{
    Latest,
    Update(Signed)
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag="Obj", content="Req")]
pub enum Request{
    TileLibrary(String, VerifierRequest)
}

#[derive(Debug, Serialize)]
#[serde(tag="Response", content="Result")]
pub enum MapResponse{
    Latest(Option<BlockHash>),
    VerifierResult(Result<BlockHash, VerifierError>)
}

struct MapThread{
    store: BlockStore,
    tile_libraries: VerifierMap,
    root_key: PublicKey
}

impl MapThread{
    fn new(store: BlockStore, root_key: PublicKey) -> MapThread{
        const TILE_LIBRARY_DIR: &'static str = "secret/tile_library/";
        const MAP_VERIFIER_KEY: &'static str = "secret/map_verifier";

        let kp = KeyPair::from_file_or_new(MAP_VERIFIER_KEY);
        let empty_namedhash = // get hash of a namedhash root signed by the MAP_VERIFIER_KEY
            store_verified(&store,
                           HashTrieMap::<String, Verifier>::new(),
                           &kp)
            .unwrap(); // XXX handle this properly
                                             
        MapThread{
            store,
            tile_libraries: VerifierMap::from_dir(TILE_LIBRARY_DIR)
                .unwrap_or_else(|e| {
                    error!("Failed to load tile library VerifierMap({}), creating new",
                           e);
                    let mut vm = VerifierMap::new(TILE_LIBRARY_DIR);
                    let allowed = HashTrieSet::new().insert(root_key.clone());
                    vm.add_new("main".into(),
                               Some(kp.clone()),
                               Some(allowed),
                               Some(empty_namedhash))
                      .unwrap(); // shouldn't be able to fail, should contain no existing
                    vm.to_dir().unwrap(); // very much can fail XXX
                    vm
                }),
            root_key,
        }
    }
    fn run(mut self, receiver: MapThreadReceiver){
        use self::Request::*;

        let mut core = tokio_core::reactor::Core::new().unwrap();
        let _handle = core.handle(); // incase we need to spawn futures

        let main = receiver.for_each(|(request, responder)| {
            responder.send(
                match request{
                    TileLibrary(name, vreq) =>
                        verifier::<NamedHash, NamedHashCommand>
                            (&self.store,
                             &mut self.tile_libraries,
                             name, vreq)
                }).unwrap();

            // XXX sync less often, this is EXTREMELY inefficient!
            self.tile_libraries
                .to_dir()
                .unwrap();
            Ok(())
        });

        core.run(main).unwrap();
    }
}

fn verifier<T, C>(store: &BlockStore, vmap: &mut VerifierMap, name: String, vreq: VerifierRequest)
    -> MapResponse
        where for <'de> T: Deserialize<'de>,
              for <'de> C: Deserialize<'de>,
              T: Serialize + ::std::fmt::Debug,
              C: Command<T>
{
    use self::VerifierRequest::{Latest as ReqLatest, *};
    use self::MapResponse::{Latest as RespLatest, *};
    match vreq{
       ReqLatest =>
           RespLatest(vmap.latest(&name)),
       Update(signed) =>
           VerifierResult(
               vmap.verify::<T,C>(store, signed, &name)
                   .wait())
    }
}

#[derive(Debug, Clone)]
pub struct MapThreadHandle(MapThreadSender);

impl MapThreadHandle{
    pub fn send(&self, req: Request)
        -> impl Future<Item=MapResponse, Error=OneshotCanceled>
    {
        let (responder, response) = oneshot();
        if let Err(_) = self.0.unbounded_send((req, responder)){
            error!("MapThread closed its Receiver!");
            panic!("MapThread closed its Receiver!");
        }
        response
    }
    pub fn tilelibrary_latest(&self, name: String)
        -> impl Future<Item=MapResponse, Error=OneshotCanceled>
    {
        self.send(Request::TileLibrary(name, VerifierRequest::Latest))
    }
    pub fn tilelibrary_update(&self, name: String, signed: Signed)
        -> impl Future<Item=MapResponse, Error=OneshotCanceled>
    {
        self.send(Request::TileLibrary(name, VerifierRequest::Update(signed)))
    }
}

pub fn spawn_thread(store: BlockStore, root_key: PublicKey) -> MapThreadHandle{
    let (sender, receiver) = unbounded_channel();

    let _thread = thread::Builder::new()
        .name("Map".into())
        .spawn(move ||{
            let map = MapThread::new(store, root_key);
            map.run(receiver);
        });

    MapThreadHandle(sender)
}


