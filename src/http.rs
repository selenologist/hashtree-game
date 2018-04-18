use hyper::server::{Http, Request, Response, Service, NewService};
use hyper::{Error as HyperError,
            header::{LastModified, Location, ContentLength, ContentType},
            mime,
            Body, Chunk};
use futures::{sync::mpsc::{UnboundedReceiver, UnboundedSender,
                           unbounded as unbounded_channel,
                           Receiver as BoundedReceiver, Sender as BoundedSender,
                           channel as bounded_channel},
              sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender,
                              channel as oneshot},
              Future, IntoFuture,
              Stream, Sink,
              Async};
use tokio_core::{self, reactor::Handle};

use std::thread;
use std::thread::{JoinHandle};
use std::io;
use std::fs;
use std::sync::{Arc, atomic::AtomicUsize};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

type ResponseFuture = Box<Future<Item=Response, Error=HyperError>>;

// files smaller than this will be sent at once instead of being chunked
const SEND_WHOLE_FILE_THRESHOLD: usize = 1<<16; // 64K
// number of chunks that fit in a File->HTTP chunk channel
const CHUNK_CHANNEL_BOUND: usize = 4;
const CHUNK_CHANNEL_SIZE:  usize = 1<<16; // 64K

pub struct RoundRobin{
    counter: AtomicUsize,
    max:     usize
}

impl RoundRobin{
    pub fn new(max: usize) -> RoundRobin{
        RoundRobin{
            counter: AtomicUsize::new(0),
            max
        }
    }
    pub fn get_next(&self) -> usize{
        use std::sync::atomic::Ordering;
        // warning: will be discontinuous at 2^64 operations due to overflow.
        // If it ever gets that high.
        self.counter.fetch_add(1, Ordering::AcqRel) % self.max
    }
}

type FileThreadRequest   = (Request, FileThreadResponder);
type FileThreadSender    = UnboundedSender<FileThreadRequest>;
type FileThreadReceiver  = UnboundedReceiver<FileThreadRequest>;
type FileThreadResponder = OneshotSender<Response>;
type FileThreadResponse  = OneshotReceiver<Response>;

struct FileThread;
impl FileThread{
    fn spawn(base_path: Arc<PathBuf>, n: usize) -> FileThreadSender{
        let (sender, receiver) = unbounded_channel();
        let _thread = thread::Builder::new()
            .name(format!("File IO {}", n))
            .spawn(move || Self::run(base_path, receiver));
        
        sender
    }
    fn handle<P: AsRef<Path>>(handle: &Handle, base_path: P, request: Request) -> Response{
        use hyper::StatusCode;
        use std::io::ErrorKind;
        use std::io::Read;
        use std::ffi::OsStr;

        let method = request.method();
        let uri  = request.uri().path();
        let path = decode_path(base_path, &request);
        trace!("{} - {} {} -> {}",
               thread::current().name().unwrap(), method, uri, path.display());
        let content_type = {
            let extension: String = {
                path.extension()
                    .and_then(|o: &OsStr| o.to_str())
                    .and_then(|s: &str| Some(String::from(s)))
                    .unwrap_or(String::new())
            };

            match extension.as_ref(){
                ""           => ContentType::octet_stream(),
                "htm"|"html" => ContentType::html(),
                "png"        => ContentType::png(),
                "js"         => ContentType("text/javascript".parse().unwrap()),
                "css"        => ContentType("text/css".parse().unwrap()),
                _            => ContentType::text_utf8()
            }
        };

        let get_meta = |path| -> io::Result<(bool, SystemTime, usize)>{
            let metadata = fs::metadata(path)?;
            let is_dir   = metadata.is_dir();
            let modified = metadata.modified()?;
            let len      = metadata.len() as usize;
            Ok((is_dir, modified, len))
        };
        let read_all = |path, len| -> io::Result<Vec<u8>>{
            let mut file = fs::File::open(path)?;
            let mut buf = Vec::with_capacity(len);
            file.read_to_end(&mut buf)?;
            Ok(buf)
        };
        let read_chunks = |path, _len| -> io::Result<BoundedReceiver<Result<Chunk, HyperError>>>{
            let file = fs::File::open(path)?;
            let (sender, receiver) = bounded_channel(CHUNK_CHANNEL_BOUND);
            let sender = sender.sink_map_err(|_| ());
            handle.spawn(ChunkReader(file).forward(sender)
                         .map(|_| ())
                         .map_err(|_| ()));
            Ok(receiver)
        };
        let generate_index = |path, uri| -> io::Result<String>{
            // should I make this easy to read, or space-efficient? 🤔
            let mut result = format!(
r#"<html><head><link rel="stylesheet" href="/dir.css"/></head><body><h1>Directory listing for {}</h1>
<table><tr><th>File</th><th>Type</th><th>Size</th></tr>"#,
                                     uri);
            for (i, res_entry) in fs::read_dir(path)?.enumerate(){
                let entry = res_entry?;
                let file_name =
                    if let Ok(fname) = entry.file_name().into_string(){
                        fname
                    }
                    else{
                        continue;
                    };
                let metadata = entry.metadata()?;
                let is_dir = metadata.is_dir();
                let size = metadata.len();
                let size_human = {
                    // B for bytes, K for Kibibytes (2^10 bytes), M, G, T, etc
                    let mut size = size;
                    let mut last_size=0;
                    let mut last_suffix='?';
                    let suffixes = ['B', 'K', 'M', 'G', 'T', 'P'].into_iter();
                    for suffix in suffixes {
                        last_size   =  size;
                        last_suffix = *suffix;
                        if size < 1024{
                            break;
                        }
                        size >>= 10; //shift by 10 is division by 1024
                    }
                    format!("{}{}", last_size, last_suffix)
                };
                let css_class =
                    if is_dir{
                        "dir"
                    }
                    else{
                        let extension = entry
                            .path()
                            .extension()
                            .and_then(|o: &OsStr| o.to_str())
                            .and_then(|s: &str| Some(String::from(s)))
                            .unwrap_or(String::new());

                        match extension.as_ref(){
                            "htm" | "html" => "htm",
                            "css"          => "css",
                            "js"           => "script",
                            "" | "bin"     => "bin",
                            _              => ""
                        }
                    };

                result.push_str(&format!(
r#"<tr class="{0}"><td><a href="{1}{4}">{1}</a></td><td class="{2}"></td><td>{3}</td></tr>"#,
                                  if i&1 == 0 { "ev" } else { "od" }, // even/odd for tables
                                  file_name, css_class, size_human, if is_dir{ "/" } else { "" }));
            }
            result.push_str(&format!("</table></body><hr/><tt>Generated by {}</html>",
                                    thread::current().name().unwrap_or("")));
            Ok(result)
        };
        let result = 
            get_meta(&path)
            .and_then(|(is_dir, modified, len): (bool, SystemTime, usize)| -> io::Result<Response>{
                Ok({
                    let response = {
                        let r = Response::new()
                            .with_header(LastModified(modified.into()))
                            .with_status(StatusCode::Ok);
                        if !is_dir{
                            r.with_header(ContentLength(len as u64))
                             .with_header(content_type)
                        }
                        else{
                            r
                        }
                    };

                    if is_dir{
                        // redirect URIs that don't end with / so that relative links will work
                        if uri.ends_with('/'){
                            let string = generate_index(path, uri)?;
                            response.with_header(ContentLength(string.len() as u64))
                                    .with_header(ContentType::html())
                                    .with_body(string)
                        }
                        else{
                            let string = "303";
                            let new_uri = format!("{}/", uri);
                            response.with_header(ContentLength(string.len() as u64))
                                    .with_header(ContentType::text())
                                    .with_header(Location::new(new_uri))
                                    .with_status(StatusCode::SeeOther)
                                    .with_body(string)
                        }
                    }
                    else if len < SEND_WHOLE_FILE_THRESHOLD{
                        response.with_body(read_all(path, len)?)
                    }
                    else{
                        response.with_body(read_chunks(path, len)?)
                    }
                })
            });

        match result{
            Ok(r) => r,
            Err(e) => {
                let status = match e.kind(){
                    ErrorKind::NotFound         => StatusCode::NotFound,
                    ErrorKind::PermissionDenied => StatusCode::Forbidden,
                    _                           => StatusCode::InternalServerError
                };
                let error_page = format!("<h1>{}</h1>", status);
                Response::new()
                    .with_header(ContentLength(error_page.len() as u64))
                    .with_header(ContentType::html())
                    .with_status(status)
                    .with_body(error_page)
            }
        }
    }

    fn run(base_path: Arc<PathBuf>, receiver: FileThreadReceiver){
        let mut core = tokio_core::reactor::Core::new().unwrap();
        let handle = core.handle();
        let recv_fut = receiver.for_each(move |(request, responder)|{
            responder.send(Self::handle(&handle, base_path.as_ref(), request))
                     .unwrap();
            Ok(())
        });
        core.run(recv_fut);
    }
}

struct FileThreadPoolInner{
    threads:   Vec<FileThreadSender>,
    scheduler: RoundRobin
}
#[derive(Clone)]
struct FileThreadPool(Arc<FileThreadPoolInner>);

impl FileThreadPool{
    fn new(n_threads: usize, base_path: Arc<PathBuf>) -> FileThreadPool {
        let threads = (0..n_threads)
            .map(|n| FileThread::spawn(base_path.clone(), n))
            .collect();

        FileThreadPool(Arc::new(FileThreadPoolInner{
            threads,
            scheduler: RoundRobin::new(n_threads)
        }))
    }
    
    fn next(&self) -> FileThreadSender{
        // access the IO thread pool in a round-robin fashion
        let current_thread = self.0.scheduler.get_next();
        self.0.threads[current_thread].clone()
    }

    fn get(&self, request: Request)
        -> FileThreadResponse
    {
        let thread = self.next();
       
        let (responder, response) = oneshot();
        thread.unbounded_send((request, responder))
            .unwrap();
        response
    }
}

#[derive(Clone)]
struct MainService{
    file_threads: FileThreadPool
}

impl Service for MainService {
    type Request  = Request;
    type Response = Response;
    type Error    = HyperError;
    type Future   = ResponseFuture;

    fn call(&self, req: Request) -> Self::Future {
        // insert additional non-file-thread responses here
        // else
        Box::new(self.file_threads.get(req).map_err(|_| HyperError::Closed))
    }
}

struct ServiceFactory{
    proto: MainService
}

impl ServiceFactory{
    fn new(n_threads: usize)
        -> ServiceFactory {
        ServiceFactory {
            proto:
                MainService{
                    file_threads: FileThreadPool::new(n_threads, Arc::new(PathBuf::from("public/".to_string())))
                }
        }
    }
}

impl NewService for ServiceFactory{
    type Request  = Request;
    type Response = Response;
    type Error    = HyperError;
    type Instance = MainService;

    fn new_service(&self) -> Result<Self::Instance, io::Error>{
        Ok(self.proto.clone())
    }
}

fn decode_path<P: AsRef<Path>>(root: P, req: &Request) -> PathBuf{
    use std::str::FromStr;
    use std::path::Component;
    use regex::{Regex, Replacer, Captures};

    lazy_static!{
        static ref PERCENT_RE: Regex =
            Regex::new("%([0-9A-Fa-f]{2})").unwrap();
    }

    struct PercentReplacer;
    impl Replacer for PercentReplacer{
        // XXX kinda hacky
        fn replace_append(&mut self, caps: &Captures, dst: &mut String){
            #[allow(non_snake_case)]
            let nybble = |digit| {
                // regex character class makes sure the character is definitely [0-9A-Fa-f]
                let zero   = '0' as u32; // chars are always 4 bytes
                let nine   = '9' as u32;
                let upperA = 'A' as u32;
                let upperF = 'F' as u32;
                let lowerA = 'a' as u32;

                if digit >= zero &&
                   digit <= nine {
                    (digit - zero) as u8
                }
                else if digit >= upperA &&
                        digit <= upperF {
                    (0xA + (digit - upperA)) as u8
                }
                else{
                    (0xA + (digit - lowerA)) as u8
                }
            };


            if let Some(hex) = caps.get(1){
                let hex   = hex.as_str();
                let upper = char::from_str(&hex[0..1]).unwrap() as u32;
                let lower = char::from_str(&hex[1..2]).unwrap() as u32;
                let byte  = (nybble(upper) << 4) |
                             nybble(lower);
                dst.push(char::from(byte));
            }
        }
    }
    
    let without_percent = PathBuf::from(String::from(
        PERCENT_RE.replace_all(req.path(), PercentReplacer))
    );
  
    // prevent directory traversal by appending to root only after processing ".."
    root.as_ref().join(
        without_percent.components().fold(PathBuf::new(),
        |mut out, c|
        match c{
            Component::Normal(x) => {
                out.push(x);
                out
            },
            Component::ParentDir => {
                out.pop();
                out
            },
            _ => out
        }))
}

struct ChunkReader(fs::File);

impl Stream for ChunkReader{ // actually blocks so is always ready from the perspective of callers (which are blocked). Never actually returns Error
    type Item = Result<Chunk, HyperError>;
    type Error = ();

    fn poll(&mut self) -> Result<Async<Option<Self::Item>>, Self::Error>{
        use std::io::ErrorKind::*;
        use std::io::Read;
        let mut buf = vec![0u8; CHUNK_CHANNEL_SIZE];
        match self.0.read(&mut buf[..]){
            Ok(bytes_read) =>
                if bytes_read == 0{ // EOF
                    return Ok(Async::Ready(None));
                }
                else {
                    buf.truncate(bytes_read);
                    return Ok(Async::Ready(Some(Ok(buf.into()))));
                },
            Err(e) => {
                return Ok(Async::Ready(Some(Err(HyperError::Io(e)))));
            }
        }
    }
}

pub fn spawn_thread()
    -> JoinHandle<()>{
    thread::Builder::new()
        .name("HTTP".into())
        .spawn(move ||{
    let addr_string = "127.0.0.1:3000";
    let addr        = addr_string.parse().unwrap();
    let factory     = ServiceFactory::new(4); // 4 IO threads
    let server      = Http::new().bind(&addr, factory).unwrap();

    info!("Starting server on http://{}", addr_string);
    server.run().unwrap();
    }).unwrap()
}

