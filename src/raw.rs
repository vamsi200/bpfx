#![allow(unused)]

pub const TASK_COMM_LEN: usize = 16;
pub const DNS_NAME_MAX: usize = 256;

#[repr(u16)]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Connect = 1,
    Accept = 2,
    Close = 3,
    Dns = 4,
    ProcessStart = 5,
    ProcessExit = 6,
    FileOpen = 7,
    FileDelete = 8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawEventHeader {
    pub timestamp_ns: u64,

    pub pid: u32,
    pub tid: u32,
    pub ppid: i32,

    pub uid: u32,
    pub gid: u32,

    pub comm: [u8; TASK_COMM_LEN],
}

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum RawProtocol {
    Tcp = 1,
    Udp = 2,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PendingConnect {
    pub protocol: u8,
    pub tid: u32,
    pub src_port: u16,
    pub dst_port: u16,

    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawConnectEvent {
    pub header: RawEventHeader,
    pub family: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawAcceptEvent {
    pub header: RawEventHeader,

    pub protocol: u8,
    pub family: u8,

    pub local_addr: [u8; 16],
    pub remote_addr: [u8; 16],

    pub local_port: u16,
    pub remote_port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawCloseEvent {
    pub header: RawEventHeader,

    pub protocol: u8,
    pub family: u8,

    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],

    pub src_port: u16,
    pub dst_port: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawDnsEvent {
    pub header: RawEventHeader,

    pub query_type: u16,

    pub query: [u8; DNS_NAME_MAX],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawProcessStartEvent {
    pub header: RawEventHeader,

    pub parent_pid: u32,

    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawProcessExitEvent {
    pub header: RawEventHeader,

    pub exit_code: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileOpenEvent {
    pub header: RawEventHeader,

    pub flags: u32,

    pub path: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileDeleteEvent {
    pub header: RawEventHeader,

    pub path: [u8; 256],
}
