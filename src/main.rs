#![feature(test)]
#![feature(conservative_impl_trait)]
#![feature(underscore_lifetimes)]
#![feature(nll)]
#![feature(fnbox)]

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
extern crate rmp;
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

//mod router;
mod block;
mod signed;
mod verify;
mod update;
mod websocket;
mod http;

mod run;
mod view;

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
                    .arg(Arg::with_name("block")
                         .short("b")
                         .index(1)
                         .required(true)));
    let args = app.clone().get_matches();
    
    if let Some(_run_args) = args.subcommand_matches("run"){
        run::main()
    }
    else if let Some(view_args) = args.subcommand_matches("view"){
        if let Some(block) = view_args.value_of("block"){
            view::main::<update::TestObject>(block.to_string())
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

