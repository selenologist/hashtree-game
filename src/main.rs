#![feature(test)]
#![feature(nll)]
#![feature(box_syntax)]
#![feature(core_intrinsics)]
extern crate test;

extern crate futures;
extern crate tokio_core;

extern crate sha2;

extern crate base64;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate rmp;
extern crate rmpv;
extern crate rmp_serde;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate rpds;
extern crate lru_cache;

extern crate sodiumoxide;

extern crate clap;

extern crate chrono;

#[macro_use]
extern crate text_io;

extern crate ws;

extern crate rand;

extern crate hyper;
extern crate mime;

extern crate regex;

#[macro_use]
extern crate lazy_static;

extern crate notify;
extern crate subprocess;

extern crate sled;

mod router;
mod block;
mod signed;
mod verify;
mod update;
//mod websocket;
mod http;
mod ltime;
mod tile;
mod map;
mod rebuilder;
mod reloader;

mod run;
mod view;

pub fn absolute_pathbuf<P: AsRef<std::path::Path>>(path: P) -> std::path::PathBuf{
    let path = path.as_ref();
    if path.is_absolute(){
        std::path::PathBuf::from(path)
    }
    else{
        std::env::current_dir().unwrap().join(path)
    }
}

// writes a file to a filename ending with "_write" (which must be unique), and then
// if it succeeds renames the successful result to the supplied filename.
// This ensures that if path already exists, then it is either replaced with a new,
// complete, valid file, or it is left alone. Thus path is not corrupted by a partial write.
pub fn write_then_rename<P, F, T>(path: P, writer: F)
    -> std::io::Result<T>
    where P: AsRef<std::path::Path>,
          F: FnOnce(&mut std::io::Write) -> std::io::Result<T>
{
    let mut file_name =
        path.as_ref()
            .file_name()
            .unwrap()
            .to_os_string();
    file_name.push(std::ffi::OsStr::new("_write"));

    let write_path = path.as_ref()
        .with_file_name(file_name);
    trace!("write_path {:?}", write_path);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&write_path)?;
    let res = writer(&mut file)?;
    if let Err(e) = std::fs::rename(write_path.clone(), path.as_ref()){
        debug!("rename {:?} -> {:?} failed, {:?}", write_path, path.as_ref(), e);
        return Err(e);
    }
    Ok(res)
}

fn main() {
    use clap::{Arg, SubCommand};
    
    env_logger::init();

    let mut app = clap::App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .subcommand(SubCommand::with_name("run")
                    .about("Run the main server"))
        .subcommand(SubCommand::with_name("view")
                    .about("View a block")
                    .arg(Arg::with_name("type")
                         .short("t")
                         .index(1)
                         .required(true)
                         .takes_value(true)
                         .possible_values(&["test", "named"]))
                    .arg(Arg::with_name("hash")
                         .short("h")
                         .index(2)
                         .required(true)));
    let args = app.clone().get_matches();
    
    if let Some(_run_args) = args.subcommand_matches("run"){
        run::main()
    }
    else if let Some(view_args) = args.subcommand_matches("view"){
        if let (Some(btype), Some(block)) =
            (view_args.value_of("type"), view_args.value_of("hash"))
        {
            view::main(btype.to_string(), block.to_string())
        }
    }
    else{
        println!("No subcommand specified.");
        app.print_long_help().unwrap();
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use test::Bencher;

}

