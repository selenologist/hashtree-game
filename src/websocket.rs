use serde::{Serialize, de::DeserializeOwned};
use rmp_serde::{to_vec_named as serialize, from_slice as deserialize};
use rmpv::{decode::read_value as read_mp_value};
use ws::{listen, Handler, Factory, Sender, Handshake, Request, Response as WsResponse, Message, CloseCode};
use ws::{Error as WsError, ErrorKind as WsErrorKind, Result as WsResult};
use futures::{Future, Stream, future::Either};
use futures::{sync::{mpsc::{UnboundedReceiver, UnboundedSender,
                            unbounded as unbounded_channel}}};
use tokio_core;
use rpds::HashTrieSet;

use std::thread;
use std::rc::Rc;
use std::sync::Arc;
use std::ops::Deref;
use std::time;
use std::path::{Path, PathBuf};
use std::io;

use block::{BlockStore, BlockHash};
use signed::{Signed, KeyPair, PublicKey};
use ltime::SerializableTime;
use map::{self, MapThreadHandle};

const CHALLENGE_BYTES: usize = 32;
const CHALLENGE_STALE_SECONDS: u64 = 5; // timestamps older than this are stale
const WEBSOCKET_KEYFILE: &'static str = "secret/websocket_key";

fn encode<T>(t: &T) -> WsResult<Message> where T: Serialize{
    serialize(t)
        .map(|m| m.into())
        .map_err(|e|{
            error!("Failed to encode to websocket {:?}", e);
            WsError::new(WsErrorKind::Protocol, "Failed to encode to websocket")
        })
}
fn decode<T>(msg: Message) -> WsResult<T> where T: DeserializeOwned{
    let slice = &msg.into_data()[..];
    deserialize(slice)
        .map_err(|e|{
            error!("Failed to decode from websocket {:?}", e);
            let mut rdr = io::Cursor::new(slice);
            match read_mp_value(&mut rdr){
                Ok(value) => {
                    error!("Expected {} got value {:?}",
                           unsafe{::std::intrinsics::type_name::<T>()}, value);
                },
                Err(e) => {
                    error!("Invalid messagepack {:?}", e);
                }
            }
            WsError::new(WsErrorKind::Protocol, "Failed to decode from websocket")
        })
}

#[derive(Serialize)]
struct ServerAuthChallenge{ // must be Signed to send to the client, still doesn't really prove the server isn't MITM replaying
    timestamp: SerializableTime,
    challenge: [u8; CHALLENGE_BYTES]
}
impl ServerAuthChallenge{
    fn new() -> ServerAuthChallenge{
        use rand::{thread_rng, Rng};
        let mut challenge: [u8; CHALLENGE_BYTES] = [0u8; CHALLENGE_BYTES];
        thread_rng().fill_bytes(&mut challenge[..]);
        ServerAuthChallenge{
            timestamp: SerializableTime::from_system_now().unwrap(),
            challenge
        }
    }
}

#[derive(Deserialize)]
struct ClientAuthResponse{
    timestamp: SerializableTime,
    challenge: [u8; CHALLENGE_BYTES]
}

impl ClientAuthResponse{
    fn check(&self, server: &ServerAuthChallenge) -> bool{
        use sodiumoxide::crypto::verify::verify_32;
        
        trace!("Checking ClientAuthResponse");
        let server_chal_time = server.timestamp.to_system();
        let client_resp_time =   self.timestamp.to_system();
        let now_time         = time::SystemTime::now();
        if         now_time.duration_since(server_chal_time)
                           .unwrap().as_secs() > CHALLENGE_STALE_SECONDS ||
           client_resp_time.duration_since(server_chal_time)
                           .unwrap().as_secs() > CHALLENGE_STALE_SECONDS{
               return false; // possible but pointless timing attack, this is cheaper than verify32
        }
        else{
            verify_32(&self.challenge, &server.challenge)
        }
    }
}

enum ClientState{
    AwaitingAuth(ServerAuthChallenge),
    Ready(PublicKey)
}

struct ServerHandler{
    state:  ClientState,
    out:    Sender,
    shared: ServerShared,
    addr:   String
}

impl Handler for ServerHandler{
    fn on_open(&mut self, hs: Handshake) -> WsResult<()>{
        if let Some(ip_addr) = hs.peer_addr {
            let ip_string = format!("{}", ip_addr);
            info!("{:>20} - connection {:?} established", ip_string, self.out.token());
            self.addr = ip_string;
        }
        else{
            debug!("Connection without IP address?");
        }

        // send authentication challenge
        if let ClientState::AwaitingAuth(ref challenge) = self.state{
            let signed = Signed::sign(challenge, &self.shared.auth)
                .map_err(|_e| WsError::new(WsErrorKind::Internal, "Failed to sign/encode ServerAuthChallenge"))?;
            self.out.send(encode(&signed)?)?;
        }
        Ok(())
    }

    fn on_request(&mut self, req: &Request) -> WsResult<WsResponse> {
        let mut res = WsResponse::from_request(req)?;

        let protocol_name = "selenologist-hash-rpg";
        res.set_protocol(protocol_name);

        Ok(res)
    }


    fn on_message(&mut self, msg: Message) -> WsResult<()>{
        use self::ClientState::*;

        let mut next_state = None;
        match self.state{
            AwaitingAuth(ref challenge) => {
                let signed: Signed = decode(msg)?;
                let user_key = signed.user.clone();
                let allowed = HashTrieSet::new().insert(user_key.clone());
                let response = signed.verify::<ClientAuthResponse>(&allowed)
                    .map_err(|_e| WsError::new(WsErrorKind::Protocol, "Failed to decode Signed ClientAuthResponse"))?;
                if response.check(&challenge){
                    trace!("{:?} authenticated!", user_key);
                    self.out.send(encode(&AuthResponse::Ok)?).unwrap();
                    next_state = Some(ClientState::Ready(user_key))
                }
                else{
                    self.out.send(encode(&AuthResponse::Err)?).unwrap();
                    self.out.close_with_reason(CloseCode::Policy, "Failed to authenticate user").unwrap();
                }
            },
            Ready(_user_key) => {
                use self::Command::*;
                let cmd: Command = decode(msg)?;
                trace!("Got {:?}", cmd);
                let out = self.out.clone();
                let fut = match cmd{
                    UploadRaw(bytes) => Either::A(
                        self.shared.store.set(Arc::new(bytes))
                            .map_err(|_| ()) // BlockStore hung up its OneshotSender
                            .map(move |r| out.send(encode(&UploadResponse::from_result(r))?))
                            .map(|_| ())
                            .map_err(|_| ())
                    ),
                    Map(req) => Either::B(
                        self.shared.map.send(req)
                            .map_err(|_| ()) // "MapThread hung up its OneshotSender"
                            .map(move |r| out.send(encode(&r)?))
                            .map(|_| ())
                            .map_err(|_| ()) // encode or send WsError
                    )
                };
                self.shared.defer.unbounded_send(Box::new(fut)).unwrap(); //XXX
            }
        }
        if let Some(next) = next_state{
            self.state = next
        }
        Ok(())
    }
}

struct ServerFactory{
    shared: ServerShared
}

impl Factory for ServerFactory{
    type Handler = ServerHandler;

    fn connection_made(&mut self, out: Sender) -> Self::Handler{
        let challenge = ServerAuthChallenge::new();
        ServerHandler{
            out,
            shared: self.shared.clone(),
            state: ClientState::AwaitingAuth(challenge),
            addr:  "0.0.0.0:0".into()
        }
    }
}

// message to thread for running block-y futures on
type DeferFuture = Box<Future<Item=(), Error=()> + Send>;
type DeferSender = UnboundedSender<DeferFuture>;
type DeferReceiver = UnboundedReceiver<DeferFuture>;

struct ServerSharedInternal{
    store: BlockStore,
    auth:  KeyPair,
    map:   MapThreadHandle,
    defer: DeferSender
}
#[derive(Clone)]
struct ServerShared(Rc<ServerSharedInternal>);

impl ServerShared{
    fn new(store: BlockStore, map: MapThreadHandle, defer: DeferSender) -> ServerShared{
        let auth = KeyPair::from_file_or_new(WEBSOCKET_KEYFILE);
        ServerShared(Rc::new(ServerSharedInternal{
            store,
            auth,
            map,
            defer
        }))
    }
}
impl Deref for ServerShared{
    type Target = ServerSharedInternal;
    fn deref(&self) -> &Self::Target{
        &*self.0
    }
}

pub fn spawn_thread(block_store: BlockStore, map_thread: MapThreadHandle)
    -> thread::JoinHandle<()>
{
    write_example_messages();

    thread::Builder::new()
        .name("websocket".into())
        .spawn(move || {
            let (defer, defer_recv): (DeferSender, DeferReceiver) =
                unbounded_channel();
            let _worker = thread::Builder::new()
                .name("ws-worker".into())
                .spawn(move ||{
                    let mut core = tokio_core::reactor::Core::new().unwrap();
                    let handle = core.handle();
                    let fut = defer_recv
                        .for_each(|f| Ok(handle.spawn(f)));
                    core.run(fut).unwrap()
                }).unwrap();

            let mut factory = ServerFactory{
                shared: ServerShared::new(block_store, map_thread, defer)
            };
            let listen_addr = "127.0.0.1:3001";
            info!("Attempting to listen on {}", listen_addr);
            listen(listen_addr, |out| factory.connection_made(out)).unwrap()
        }).unwrap()
}

// command format below
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag="Cmd", content="Data")]
enum Command{
    UploadRaw(Vec<u8>),
    Map(map::Request)
}


#[derive(Deserialize, Serialize)]
#[serde(tag="Response", content="Result")]
enum UploadResponse{
    Ok(BlockHash),
    Err(String)
}

impl UploadResponse{
    fn from_result(result: io::Result<BlockHash>) -> UploadResponse{
        match result{
            Ok(k) => UploadResponse::Ok(k),
            Err(e) => UploadResponse::Err(format!("{:?}", e))
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(tag="Auth")]
enum AuthResponse{
    Ok,
    Err
}

fn example<P: AsRef<Path>, S: Serialize>(dir: P, filename: &'static str, message: S)
    -> ::std::io::Result<()>
{
    use std::fs;
    use std::io;
    use std::io::Write;

    let filename = Path::new(filename);
    let p: PathBuf = dir.as_ref().join(filename);
    let mut f = fs::File::create(&p)?;
    let v = serialize(&message)
        .map_err(|e| io::Error::new(io::ErrorKind::Other,
                                    e))?;
    f.write_all(v.as_ref())
}

fn write_example_messages(){
    const EXAMPLE_MSG_DIR: &'static str = "example_msg/";
    use std::fs;
    use std::io;
    use update::{Update, NamedHashCommand};
    use block::BlockHash;
    use ltime::SerializableTime;

    fs::create_dir_all(EXAMPLE_MSG_DIR).expect("Failed to create example message dir");
    let dir = Path::new(EXAMPLE_MSG_DIR);
    
    let all = move || -> io::Result<()>{
        example(dir, "ServerAuthChallenge", ServerAuthChallenge::new())?;
        example(dir, "MapCommand_TileLibrary_Latest",
               Command::Map(map::Request::TileLibrary("main".into(),
                                                      map::VerifierRequest::Latest)))?;

        let update =
            Update{
                timestamp: SerializableTime::from_system_now().unwrap(),
                command:
            NamedHashCommand::Set("smile".into(),
                                  BlockHash::from("l6RV2N6qQRjHCvKZ47adEXMf51YwEiIj2qiKcs-7L9Y")),
                last: BlockHash::from("ABC123")
            };
        example(dir, "UpdateSmilePresign", update)?;

        let update =
            Update{
                timestamp: SerializableTime::from_system_now().unwrap(),
                command:
            NamedHashCommand::Set("smile".into(),
                                  BlockHash::from("l6RV2N6qQRjHCvKZ47adEXMf51YwEiIj2qiKcs-7L9Y")),
                last: BlockHash::from("ABC123")
            };

        let kp = KeyPair::generate();
        let signed = Signed::sign(update,
                                  &kp).unwrap();
        example(dir, "MapCommand_TileLibrary_UpdateMainWithSmile",
               Command::Map(map::Request::TileLibrary("main".into(),
                                                      map::VerifierRequest::Update(signed))))?;

        example(dir, "UploadRaw_hello",
               Command::UploadRaw("hello".into()))
    };
    all().unwrap_or_else(|e| error!("write_example_messages error: {:?}", e));
}
/*
pub mod base64_chalresp{
    use serde::{Deserialize, Serializer, Deserializer};
    use base64::{self, URL_SAFE_NO_PAD};
    use super::CHALLENGE_BYTES;

    pub fn serialize<S>(t: &[u8; CHALLENGE_BYTES], serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        let s = base64::encode_config(t.as_ref(), URL_SAFE_NO_PAD);
        serializer.serialize_str(&s)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; CHALLENGE_BYTES], D::Error>
        where D: Deserializer<'de>
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        let bytes = base64::decode_config(&s, URL_SAFE_NO_PAD)
            .map_err(|e| Error::custom(e.to_string()))?;
        let mut array = [0u8; CHALLENGE_BYTES];
        for i in 0..CHALLENGE_BYTES{
            array[i] = bytes[i]
        }
        Ok(array)
    }
}
*/
