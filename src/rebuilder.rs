use notify::{DebouncedEvent, Watcher, RecursiveMode, watcher};
use subprocess::{Exec, ExitStatus};
use futures::{future, future::Either, Future, Stream, Sink, Poll, Async};

use router::PubSubHandle;

use std::sync::mpsc::{channel as std_channel};
use std::time::Duration;
use std::io;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::thread::{JoinHandle};
use std::sync::Arc;

pub type FilePath = Arc<PathBuf>;

#[derive(Debug, Clone)]
pub enum FileEvent{
    Added(FilePath),
    Removed(FilePath),
    Modified(FilePath),
    Renamed(FilePath, FilePath)
}    

fn process_coffee(path: &Path) -> io::Result<()>{
    info!("Compiling {}", path.to_str().unwrap());
    let exit_status = match
        Exec::cmd("coffee")
        .arg("-c")
        .arg(path)
        .join(){
            Ok(k) => k,
            Err(e) => return Err(io::Error::new(io::ErrorKind::Other, format!("{:?}", e)))
    };

    if exit_status != ExitStatus::Exited(0){
        error!("Error, returned {:?}", exit_status);
        Err(io::Error::new(io::ErrorKind::Other, format!("exited with status {:?}", exit_status)))
    }
    else{
        info!("{} processed.", path.to_str().unwrap());
        Ok(())
    }
}

fn check<P: AsRef<Path>>(path: P){
    match path.as_ref().extension(){
        Some(ext) if ext == "coffee" => {
            match process_coffee(path.as_ref()){
                Ok(..) => {},
                Err(e) => error!("Failed to process: {:?}", e)
            }
        },
        _ => {}
    }
}


fn recursive_find(path: &Path) -> io::Result<()>{
    trace!("Entering {}", path.to_str().unwrap());
    for p in fs::read_dir(path)?{
        let e = p.unwrap();
        trace!("Found file {:?}", e.file_name());
        if e.file_type().unwrap().is_dir(){
            recursive_find(&e.path())?;
        }
        if e.file_type().unwrap().is_file(){
            let path = e.path();
            check(path)
        }
    }
    Ok(())
}

fn handle_event(event: DebouncedEvent, pubsub: &PubSubHandle<FileEvent>){
    use self::DebouncedEvent::*;
    use self::FileEvent::*;

    let broadcast = move |s| pubsub.send("FileUpdate".into(), Arc::new(s));
    fn to_str<'a>(p: &'a PathBuf) -> &'a str{
        p.to_str().unwrap_or("<nonunicode>")
    }
    // XXX maybe do check after broadcast?
    match event{
        Create(p) => {
            info!("File {} added", to_str(&p));
            check(&p);
            broadcast(Added(Arc::new(p)));
        },
        Write(p)  => {
            info!("File {} modified", to_str(&p));
            check(&p);
            broadcast(Modified(Arc::new(p)));
        },
        Rename(old, new) => {
            info!("File {} renamed to {}", to_str(&old), to_str(&new));
            check(&new);
            broadcast(Renamed(Arc::new(old), Arc::new(new)));
        },
        Remove(p) => {
            info!("File {} removed", to_str(&p));
            broadcast(Removed(Arc::new(p)));
        }
        _ => ()
    }
}

pub fn spawn_thread(pubsub: PubSubHandle<FileEvent>){
    let _thread = thread::Builder::new()
        .name("rebuilder".into())
        .spawn(move ||{
        let watch_path = "public/";
        trace!("Finding and processing existing .coffee files");
        recursive_find(Path::new(watch_path)).unwrap();

        let (watcher_tx, watcher_rx) = std_channel();

        let mut watcher = watcher(watcher_tx, Duration::from_millis(200)).unwrap();

        watcher.watch(watch_path, RecursiveMode::Recursive).unwrap();

        loop{
            match watcher_rx.recv(){
                Ok(ev) => handle_event(ev, &pubsub),
                Err(e) => error!("watch error: {:?}", e)
            }
        }
    }).unwrap();
}
