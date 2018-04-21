use rmp_serde::{from_slice as deserialize};
use rpds::HashTrieSet;
use serde::{Deserialize, Serialize};
use chrono::{self, TimeZone};
use futures::Future;
use base64;

use std::path::PathBuf;
use std::sync::Arc;
use std::fmt::Debug;

use update::{Update, Command, TestCommand, TestObject, NamedHash, NamedHashCommand};
use signed::{Signed};
use block::{BlockHash, BlockStore, spawn_thread as spawn_block_thread};
use verify::*;


type NavigationString = String;
type NavigationFunction = Box<Fn(BlockStore) -> NavigationResult>;
type NavigationList = Vec<(NavigationString, NavigationFunction)>;
// new enum instead of type alias to permit cyclic closure
enum NavigationResult{
    NOk(NavigationList),
    NErr(String)
}

// XXX: Somehow make this properly generic

fn decode_vd<T, C>(block_store: BlockStore, block_hash: BlockHash) -> NavigationResult
    where T: Serialize + Debug,
          C: Command<T>,
    for <'de> T: Deserialize<'de>,
    for <'de> C: Deserialize<'de>
{
    use self::NavigationResult::*;
    let mut next: Vec<(NavigationString, Box<Fn(BlockStore) -> NavigationResult>)> = Vec::new();
    match block_store.get(block_hash.clone()).wait(){
        Ok(Ok(block)) => {
            let signed: Signed = match deserialize(&block[..]){
                Ok(k) => k,
                Err(e) => {
                    return NErr(format!("{:?} failed to decode to Signed: {:?}", block_hash, e));
                }
            };
            let signed_user_b64 = base64::encode_config(&signed.user, base64::URL_SAFE_NO_PAD);

            let allow_any = HashTrieSet::new().insert(signed.user.clone());
            let verified = match signed.verify::<VerifiedData<T>>(&allow_any){
                Ok(u) => u,
                Err(e) => {
                    return NErr(format!("invalid VerifiedData: {:?}", e));
                }
            };
            
            println!("{:?} verified by {}:\n\tvalue: {:?}", block_hash, signed_user_b64, verified.value);
            if let Some(update) = verified.update{
                let update_user = update.user.clone();
                let update_user_b64 = base64::encode_config(&update_user, base64::URL_SAFE_NO_PAD);

                match update.verify::<Update<C>>(&allow_any.insert(update_user)){
                    Ok(update) => {
                        let time = chrono::Local.timestamp(update.timestamp.to_u64() as i64, 0).to_rfc3339();
                        let update_last = update.last.clone();
                        
                        println!("\tupdate:\n\t\tby key {}\n\t\tat {}\n\t\tto last {:?}", update_user_b64, time, update_last);
                        
                        let next_fn = Box::new(move |bs: BlockStore| -> NavigationResult {decode_vd::<T, C>(bs, update_last.clone())});
                        next.push(("last".into(), next_fn));
                    },
                    Err(err) => {
                        return NErr(format!("\tinvalid update {:?} by {}", err, update_user_b64));
                    }
                }
            }
            else{
                println!("\tthis is a root block");
            }
            NOk(next)
        },
        Ok(Err(e)) => {
            NErr(format!("{:?} failed to load: {:?}", block_hash, e))
        },
        Err(e) => {
            NErr(format!("BlockStore thread hang up its receiver! {:?}", e))
        }
    }
}

fn navigate<F>(block_store: &BlockStore, depth: usize, f: Box<F>)
    where F: Fn(BlockStore) -> NavigationResult + ?Sized
{
    use self::NavigationResult::*;
    loop{
        println!("*N* Navigation depth {}", depth);
        let next = match f(block_store.clone()){
            NOk(n) => n,
            NErr(e) => {
                println!("Error: {:?}, navigating up", e);
                return;
            }
        };
        println!("*N* Navigation choices:\n0: {}", if depth > 0 { "up" } else { "exit" });
        for (i, option) in next.iter().enumerate(){
            let &(ref choice, _) = option;
            println!("{}: {}", i + 1, choice);
        }
        let i: usize = read!();
        if i == 0{
            break;
        }
        else if (i - 1) < next.len(){
            let i = i - 1;
            // move next[i] out of next
            let (_, next_f) = next.into_iter().nth(i).unwrap();
            navigate(block_store, depth + 1, next_f);
        }
        else{
            println!("*N* Invalid input.");
        }
    }
}

pub fn main(type_string: String, block_string: String)
{
    let block_store = spawn_block_thread(PathBuf::from("public/blocks/"));
    let block_hash = BlockHash(Arc::new(block_string));
    let next = Box::new(move |bs: BlockStore| -> NavigationResult {
        match type_string.as_str(){
            "test"  =>
                decode_vd::<TestObject, TestCommand>(bs, block_hash.clone()),
            "named" =>
                decode_vd::<NamedHash, NamedHashCommand>(bs, block_hash.clone()),
            _ =>
                panic!("Invalid block type {}", type_string)
        }
    });
    navigate(&block_store, 0, next);
}

