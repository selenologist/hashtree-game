use serde::{Serialize, Deserialize};

use std::marker::PhantomData;

use verify::*;
use block::*;

pub trait Command<'a>: Serialize + Deserialize<'a>{
    type In: Serialize + Deserialize<'a>;
    type Out: Serialize;
    fn process(&self, input: Self::In) -> Result<Self::Out, ()>;
    fn into_update(self, last: BlockHash) -> Update<'a, Self::In, Self>{
        Update{
            timestamp: SerializableTime::from_system_now().unwrap(),
            command: self,
            last,
            phantom: PhantomData
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Update<'a, T: 'a + Serialize + Deserialize<'a>, C: Command<'a, In=T, Out=T>>{ 
  pub timestamp: SerializableTime,
  pub command: C,
  pub last:    BlockHash,
  phantom: PhantomData<&'a T>
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, Default)]
pub struct TestObject(u64);

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum TestCommand{
    Add(u64)
}

impl<'d> Command<'d> for TestCommand{
    type In = TestObject;
    type Out = TestObject;
    fn process(&self, input: Self::In) -> Result<Self::Out, ()>{
        match *self{
            TestCommand::Add(y) => {
                let TestObject(x) = input;
                Ok(TestObject(x + y))
            },
            _ => Err(())
        }
    }
}
