use serde::{Serialize};

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
