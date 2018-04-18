use serde::{Serialize, de::DeserializeOwned};
use rmp_serde::{to_vec as serialize, from_slice as deserialize};
use ws::{listen, Handler, Factory, Sender, Handshake, Request, Response as WsResponse, Message, CloseCode};
use ws::{Error as WsError, ErrorKind as WsErrorKind, Result as WsResult};
use rpds::HashTrieSet;

use std::thread;
use std::rc::Rc;
use std::ops::Deref;

use block::*;
use verify::*;
use signed::*;

const CHALLENGE_BYTES: usize = 32;
const WEBSOCKET_KEYFILE: &'static str = "secret/websocket_key";

fn encode<T>(t: &T) -> WsResult<Message> where T: Serialize{
    serialize(t)
        .map(|m| m.into())
        .map_err(|_e| WsError::new(WsErrorKind::Protocol, "Failed to encode to messagepack"))
}
fn decode<T>(msg: Message) -> WsResult<T> where T: DeserializeOwned{
    deserialize(&msg.into_data()[..])
        .map_err(|_e| WsError::new(WsErrorKind::Protocol, "Failed to decode from messagepack"))
}

#[derive(Serialize)]
struct ServerAuthChallenge{ // must be Signed to send to the client, still doesn't really prove the server isn't MITM replaying
    timestamp: SerializableTime,
    challenge: [u8; CHALLENGE_BYTES] // consider if this should use a better PRNG
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
    response:  [u8; CHALLENGE_BYTES]
}

impl ClientAuthResponse{
    fn check(&self, server: &ServerAuthChallenge) -> bool{
        use sodiumoxide::crypto::verify::verify_32;
        verify_32(&self.response, &server.challenge)
    }
}

enum ClientState{
    AwaitingAuth(ServerAuthChallenge),
    Ready(AllowedKeys)
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
            let signed = Signed::sign(challenge, &self.shared.auth.pubkey, &self.shared.auth.secret)
                .map_err(|_e| WsError::new(WsErrorKind::Internal, "Failed to sign/encode ServerAuthChallenge"))?;
            self.out.send(encode(&signed)?)?;
        }
        Ok(())
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
                    next_state = Some(ClientState::Ready(allowed))
                }
                else{
                    self.out.close_with_reason(CloseCode::Policy, "Failed to authenticate user").unwrap();
                }
            },
            _ => ()
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

impl ServerFactory{
    fn new(store: BlockStore) -> ServerFactory{
        ServerFactory{
            shared: ServerShared::new(store)
        }
    }
}

#[derive(Debug, Clone)]
struct ServerShared(Rc<ServerSharedInternal>);
#[derive(Debug)]
struct ServerSharedInternal{
    store: BlockStore,
    auth:  KeyPair
}
impl ServerShared{
    fn new(store: BlockStore) -> ServerShared{
        let auth = KeyPair::from_file_or_new(WEBSOCKET_KEYFILE);
        ServerShared(Rc::new(ServerSharedInternal{
            store,
            auth
        }))
    }
}
impl Deref for ServerShared{
    type Target = ServerSharedInternal;
    fn deref(&self) -> &Self::Target{
        &*self.0
    }
}

pub fn spawn_thread(block_store: BlockStore) -> thread::JoinHandle<()>{
    thread::Builder::new()
        .name("websocket".into())
        .spawn(move || {
            let mut factory = ServerFactory::new(block_store);
            let listen_addr = "127.0.0.1:3001";
            info!("Attempting to listen on {}", listen_addr);
            listen(listen_addr, |out| factory.connection_made(out)).unwrap()
        }).unwrap()
}

