#![allow(unused)]

use std::net::IpAddr;

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
