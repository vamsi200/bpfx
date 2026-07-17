#![allow(unused)]
use std::{fmt::Display, net::IpAddr, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessId {
    pub pid: u32,
    pub tid: u32,
}

#[derive(Debug, Clone)]
pub struct EventHeader {
    pub timestamp_ns: u64,

    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,

    pub uid: u32,
    pub gid: u32,

    /// Process Name
    pub comm: String,
}

impl Display for EventHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} pid={} tid={} ppid={} uid={} gid={} comm={}",
            self.timestamp_ns, self.pid, self.tid, self.ppid, self.uid, self.gid, self.comm,
        )
    }
}

impl EventHeader {
    pub fn process(&self) -> ProcessId {
        ProcessId {
            pid: self.pid,
            tid: self.tid,
        }
    }

    pub fn is_kernel_thread(&self) -> bool {
        self.pid == 0
    }

    pub fn timestamp(&self) -> Duration {
        Duration::from_nanos(self.timestamp_ns)
    }
}
