use tokio_core::reactor::{self, Handle as TokioHandle};
use futures::{sync::mpsc::{UnboundedReceiver, UnboundedSender,
                           unbounded as unbounded_channel},
              sync::oneshot::{Receiver as OneshotReceiver, Sender as OneshotSender,
                              channel as oneshot},
              Stream};

use std::collections::{HashMap};
use std::sync::Arc;
use std::thread;
use std::any::Any;
use std::fmt::Debug;

type Message<T> = Arc<T>; 

#[derive(Copy, Clone, Debug, Default, Hash, PartialEq, Eq)]
struct TopicClientId(u32);
impl TopicClientId{
    fn next(&self) -> TopicClientId {
        let TopicClientId(x) = *self;
        TopicClientId(x + 1)
    }
}

type MessageSender<T>  = UnboundedSender<Message<T>>;
type MessageReceiver<T>  = UnboundedReceiver<Message<T>>;
type TopicAttachResponder<T> = OneshotSender<TopicHandle<T>>;
pub type TopicAttachResponse<T> = OneshotReceiver<TopicHandle<T>>;

#[derive(Debug)]
enum TopicUpdate<T: Sync + Send>{
    Attach(TopicAttachResponder<T>),
    Activate(TopicClientId),
    Deactivate(TopicClientId),
    Detach(TopicClientId),
    Data(Message<T>),
}

type TopicSender<T>   = UnboundedSender<TopicUpdate<T>>;
type TopicReceiver<T> = UnboundedReceiver<TopicUpdate<T>>;

struct TopicClient<T: Sync + Send>{
    pub active: bool, // whether messages will be relayed or if this receiver is temporarily muted
    pub sender: MessageSender<T>
}

impl<T: Sync + Send> TopicClient<T>{
    pub fn new(sender: MessageSender<T>) -> TopicClient<T>{
        TopicClient{
            active: true,
            sender
        }
    }
}

struct Topic<T:Sync + Send>{
    sender:   TopicSender<T>,
    // actually move this out into spawn so that we don't double-borrow &mut self   receiver: TopicReceiver,
    clients:  HashMap<TopicClientId, TopicClient<T>>,
    next_id:  TopicClientId
}

impl<T: Sync + Send + Debug + 'static> Topic<T>{
    fn attach(&mut self) -> TopicHandle<T>{
        let id = loop { // keep trying keys until we have a new one (in the typical case this doesn't loop, if all 2^32 keys are used somehow, loops forever)
            let id = self.next_id;
            self.next_id = self.next_id.next();
            if !self.clients.contains_key(&id){
                break id; // this is an unused key, use it
            }
        };
        let (tx, receiver) = unbounded_channel();
        let client = TopicClient::new(tx);
        self.clients.insert(id, client);
        TopicHandle::new(id, self.sender.clone(), receiver)
    }
    fn detach(&mut self, id: TopicClientId){
        self.clients.remove(&id);
    }
    fn repeat(&mut self, message: Message<T>){
        // XXX: consider manually stepping the iterator so we can detect the last element and not
        // do a pointless clone
        self.clients.retain(|_, client|{
            if client.active{
                match client.sender.unbounded_send(message.clone()){
                    Ok(_)  => true, //valid, keep
                    Err(e) =>
                        // XXX: log this?
                        false
                }
            }
            else{
                true // still valid, keep
            }
        });
    }
    fn set_active(&mut self, id: TopicClientId, active: bool){
        if let Some(client) = self.clients.get_mut(&id){
            client.active = active;
        }
    }
    fn activate(&mut self, id: TopicClientId){
        self.set_active(id, true);
    }
    fn deactivate(&mut self, id: TopicClientId){
        self.set_active(id, false);
    }

    pub fn spawn(handle: &TokioHandle) -> TopicSender<T>{
        use self::TopicUpdate::*;

        let (sender, receiver) = unbounded_channel();
        let mut this =
            Topic{
                sender: sender.clone(),
                clients: HashMap::new(),
                next_id: TopicClientId::default()
            };
        handle.spawn(receiver.for_each(
            move |update| {
                match update{
                    Attach(responder) =>
                        {responder.send(this.attach())
                                  .expect("Failed to send topic attachment")},
                    Activate(id) =>
                        this.activate(id),
                    Deactivate(id) =>
                        this.deactivate(id),
                    Detach(id) =>
                        this.detach(id),
                    Data(message) =>
                        this.repeat(message)
                }
                Ok(())
            })
        );
        sender
    }
}

#[derive(Debug)]
pub struct TopicHandle<T: Sync + Send>{
    id:           TopicClientId,
    sender:       TopicSender<T>,
    pub receiver: MessageReceiver<T>,
}

impl<T: Sync + Send> TopicHandle<T>{
    fn new(id: TopicClientId, sender: TopicSender<T>, receiver: MessageReceiver<T>) 
        -> TopicHandle<T>
    {
        TopicHandle{
            id,
            sender,
            receiver
        }
    }

    pub fn activate(&self){
        self.sender.unbounded_send(TopicUpdate::Activate(self.id)).unwrap();
    }
    pub fn deactivate(&self){
        self.sender.unbounded_send(TopicUpdate::Deactivate(self.id)).unwrap();
    }
    pub fn send(&self, data: Message<T>){
        self.sender.unbounded_send(TopicUpdate::Data(data)).unwrap();
    }
    pub fn detach(self){ // consumes the handle
        self.sender.unbounded_send(TopicUpdate::Detach(self.id)).unwrap();
    }
}

enum PubSubUpdate<A: Any + Sync + Send>{
    // created if doesn't exist
    Attach{ id: String, responder: TopicAttachResponder<A> }, 
    // no-op if doesn't exist (because there can't be any clients)
    Send{ id: String, message: Message<A> },
}

type PubSubSender<A> = UnboundedSender<PubSubUpdate<A>>;
type PubSubReceiver<A> = UnboundedReceiver<PubSubUpdate<A>>;

#[derive(Clone)]
pub struct PubSubHandle<A>(PubSubSender<A>) where A: Sync + Send + 'static;

pub struct PubSub;
impl PubSub{
    fn run<A>(receiver: PubSubReceiver<A>)
        where A: Any + Sync + Send + Debug
    {
        use self::PubSubUpdate::*;
        let mut topics = HashMap::<String, TopicSender<A>>::new();
        let mut core = reactor::Core::new().unwrap();
        let handle = core.handle();
        core.run(receiver.for_each(move |update|{
            match update{
                Attach{ id, responder } => {
                    let sender = topics.entry(id).or_insert(Topic::spawn(&handle)).clone();
                    sender.unbounded_send(TopicUpdate::Attach(responder))
                          .unwrap();
                },
                Send{ id, message } => {
                    if let Some(sender) = topics.get(&id){
                        sender.unbounded_send(TopicUpdate::Data(message))
                              .unwrap();
                    }
                }
            }
            Ok(())
        }));
    }

    pub fn spawn_thread<A>() -> PubSubHandle<A>
        where A: Any + Sync + Send + Debug
    {
        use self::PubSubUpdate::*;

        let (sender, receiver) = unbounded_channel();
        
        let _thread = thread::Builder::new()
            .name("PubSub".into())
            .spawn(move || Self::run(receiver));

        PubSubHandle(sender)
    }
}

impl<A: Any + Sync + Send + Debug> PubSubHandle<A>{
    pub fn attach(&self, id: String) -> TopicAttachResponse<A>{
        let (responder, receiver) = oneshot();
        self.0.unbounded_send(PubSubUpdate::Attach{ id, responder }).unwrap();
        receiver
    }
    pub fn send(&self, id: String, message: Message<A>){
        self.0.unbounded_send(PubSubUpdate::Send{ id, message }).unwrap();
    }
}
