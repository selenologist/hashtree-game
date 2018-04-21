use ws::{Handler, Factory, Sender, Handshake, Request, Response as WsResponse, CloseCode, WebSocket};
use ws::{Result as WsResult};
use futures::{Future, Stream};
use log::Level;

use std::thread;

use rebuilder::FileEvent;
use router::PubSubHandle;

// does nothing but keep the connection open and keep address if trace is on
#[derive(Default)]
struct NullHandler{
    addr: Option<String>
}
struct ServerFactory; // builds NullHandlers

impl Handler for NullHandler{
    fn on_open(&mut self, hs: Handshake) -> WsResult<()>{
        if log_enabled!(Level::Trace){ // don't bother populating addr if not Tracing
            if let Some(ip_addr) = hs.peer_addr {
                let ip_string = format!("{}", ip_addr);
                info!("{:>20} - connection established",
                      ip_string);
                self.addr = Some(ip_string);
            }
        }
        Ok(())
    }

    fn on_request(&mut self, req: &Request) -> WsResult<WsResponse> {
        let mut res = WsResponse::from_request(req)?;

        let protocol_name = "selenologist-minimal-reloader";
        res.set_protocol(protocol_name);

        Ok(res)
    }

    fn on_close(&mut self, code: CloseCode, reason: &str){
        trace!("Closing connection {:?} because {:?} {}", self.addr, code, reason);
    }
}

impl Factory for ServerFactory{
    type Handler = NullHandler;

    fn connection_made(&mut self, _out: Sender) -> Self::Handler{
        NullHandler::default()
    }
}

pub fn spawn_thread(pubsub: PubSubHandle<FileEvent>)
{
    let _thread = thread::Builder::new()
        .name("reloader".into())
        .spawn(move || {
            let factory = ServerFactory;
            let listen_addr = "127.0.0.1:3002";
            info!("Attempting to listen on {}", listen_addr);
            let server = WebSocket::new(factory).unwrap();
            let broadcaster = server.broadcaster();
            info!("Waiting until reloader attached to FileUpdate topic");
            let topic = pubsub
                .attach("FileUpdate".into())
                .wait()
                .unwrap();
            info!("Reloader attached");

            // lazily spawn another thread to handle the file events
            let handle = thread::Builder::new()
                .name("reload bcast".into())
                .spawn(move || {
                    topic.receiver.for_each(|ev|{
                        use rebuilder::{FilePath, FileEvent::*};
                        let check = |p: &FilePath|{
                            trace!("reloader checking {:?}", p);
                            match p.extension().and_then(|os| os.to_str()){
                                Some("html") |
                                Some("htm")  |
                                Some("css")  |
                                Some("js") => {
                                    trace!("sending reload");
                                    broadcaster.send("Reload").unwrap();
                                }
                                _ => {}
                            }
                        };
                        match *ev{
                            Added(ref p)       |
                            Modified(ref p)    => check(p),
                            Renamed(.., ref d) => check(d),
                            _ => {}
                        };
                        Ok(())
                    }).wait().unwrap()
                }).unwrap();
            server.listen(listen_addr).unwrap();
            let join = handle.join();
            panic!("reloader broadcast thread joined: {:?}", join)
        }).unwrap();
}

