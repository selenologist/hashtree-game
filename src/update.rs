use serde::{Serialize};
use rpds::HashTrieMap;

//use std::marker::PhantomData;

use verify::*;
use block::*;

pub trait Command<T: Sized + Serialize>: Serialize{
    fn process(&self, input: T) -> Result<T, ()>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Update<T>{ 
  pub timestamp: SerializableTime,
  pub command: T,
  pub last:    BlockHash,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Default)]
pub struct TestObject(u64);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum TestCommand{
    Add(u64)
}

impl TestCommand{
    pub fn into_update(self, last: BlockHash) -> Update<TestCommand>{
        Update{
            timestamp: SerializableTime::from_system_now().unwrap(),
            command: self,
            last,
        }
    }
}

impl Command<TestObject> for TestCommand{
    fn process(&self, input: TestObject) -> Result<TestObject, ()>{
        match *self{
            TestCommand::Add(y) => {
                let TestObject(x) = input;
                Ok(TestObject(x + y))
            },
        }
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq, Hash)]
pub struct TileId(u8);

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Tileset{
    // this would use a lot less memory if we implemented a Verifier-side cache that kept objects
    // in-memory indexed by their hash when serialized, so that they aren't retrieved from the
    // serialized copy.
    pub tile_png: HashTrieMap<TileId, BlockHash>
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TilesetCommand{
    Set(TileId, BlockHash),
}

impl Command<Tileset> for TilesetCommand{
    fn process(&self, old: Tileset) -> Result<Tileset, ()>{
        match *self{
            TilesetCommand::Set(id, ref hash) => {
                Ok(Tileset{
                    tile_png: old.tile_png.insert(id, hash.clone())
                })
            },
        }
    }
}

