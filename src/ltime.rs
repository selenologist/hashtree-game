use std::time::{UNIX_EPOCH, Duration, SystemTime, SystemTimeError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SerializableTime(u32); // TEMPORARILY make this u32. // u64 seconds since unix epoch

impl SerializableTime{
    pub fn from_system(sys: SystemTime) -> Result<SerializableTime, SystemTimeError>{
        sys.duration_since(UNIX_EPOCH)
           .map(|sys_since_unix| SerializableTime(sys_since_unix.as_secs() as u32))
    }
    pub fn from_system_now() -> Result<SerializableTime, SystemTimeError>{
        Self::from_system(SystemTime::now())
    }
    pub fn to_system(&self) -> SystemTime{
        use std::ops::Add;
        let &SerializableTime(secs_since_epoch) = self;
        UNIX_EPOCH.clone().add(Duration::from_secs(secs_since_epoch as u64))
    }
    pub fn to_u64(&self) -> u64{
        let &SerializableTime(u) = self;
        u as u64
    }
}

pub fn check_stale(virtual_now: SystemTime, timestamp: SystemTime, stale_seconds: u64) -> bool{
    if let Ok(duration) = virtual_now.duration_since(timestamp){
        trace!("time difference {}", duration.as_secs());
        if duration.as_secs() < stale_seconds{
            return false;
        }
    }
    else{
        trace!("Failed to get duration between {:?} and {:?}", virtual_now, timestamp);
    }
    true
}

pub fn now_check_stale(timestamp: SystemTime, stale_seconds: u64) -> bool{
    check_stale(SystemTime::now(), timestamp, stale_seconds)
}
