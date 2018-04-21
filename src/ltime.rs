use serde::{Serialize, Deserialize};

use std::time::{UNIX_EPOCH, Duration, SystemTime, SystemTimeError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableTime(u64); // u64 seconds since unix epoch

impl SerializableTime{
    pub fn from_system(sys: SystemTime) -> Result<SerializableTime, SystemTimeError>{
        sys.duration_since(UNIX_EPOCH)
           .map(|sys_since_unix| SerializableTime(sys_since_unix.as_secs()))
    }
    pub fn from_system_now() -> Result<SerializableTime, SystemTimeError>{
        Self::from_system(SystemTime::now())
    }
    pub fn to_system(&self) -> SystemTime{
        use std::ops::Add;
        let &SerializableTime(secs_since_epoch) = self;
        UNIX_EPOCH.clone().add(Duration::from_secs(secs_since_epoch))
    }
    pub fn to_u64(&self) -> u64{
        let &SerializableTime(u) = self;
        u
    }
}

pub fn check_stale(virtual_now: SystemTime, timestamp: SystemTime, stale_seconds: u64) -> bool{
    if let Ok(duration) = virtual_now.duration_since(timestamp){
        if duration.as_secs() < stale_seconds{
            return false;
        }
    }
    true
}

pub fn now_check_stale(timestamp: SystemTime, stale_seconds: u64) -> bool{
    check_stale(SystemTime::now(), timestamp, stale_seconds)
}
