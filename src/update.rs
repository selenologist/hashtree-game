use serde::{Serialize};
use rpds::HashTrieMap;

use std::fmt::{self, Debug};

use block::BlockHash;
use ltime::SerializableTime;

pub trait Command<T: Sized + Serialize>: Serialize{
    fn process(self, input: T) -> Result<T, ()>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Update<T>{ 
  pub timestamp: SerializableTime,
  pub command: T,
  pub last:    BlockHash,
}

// XXX rename this
// XXX should cache unserialized blocks so that HashTrieMap can share memory
/// Maps String names to a BlockHash, maintaining a persistant log like any other Verifier<Command<T>>
#[derive(Serialize, Deserialize, Default)]
pub struct NamedHash(pub HashTrieMap<String, BlockHash>);

// print a little bit prettier so it can actually be read
impl Debug for NamedHash{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error>{
        write!(f, "\nNamedHash{{\n")?;
        for (k,v) in self.0.iter(){
            write!(f, "\t{:?}: {:?}\n", k, v)?;
        }
        write!(f, "}}")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag="Cmd", content="Data")]
pub enum NamedHashCommand{
    Set(String, BlockHash),
}

impl Command<NamedHash> for NamedHashCommand{
    fn process(self, old: NamedHash) -> Result<NamedHash, ()>{
        match self{
            NamedHashCommand::Set(id, hash) => {
                Ok(NamedHash(old.0.insert(id, hash)))
            },
        }
    }
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
    fn process(self, input: TestObject) -> Result<TestObject, ()>{
        match self{
            TestCommand::Add(y) => {
                let TestObject(x) = input;
                Ok(TestObject(x + y))
            },
        }
    }
}
