#![no_std]
#![allow(unused)]
pub const TASK_COMM_LEN: usize = 16;
pub const DNS_NAME_MAX: usize = 256;

#[repr(u8)]
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
    FileClose = 9,
}

impl TryFrom<u8> for EventType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Connect),
            2 => Ok(Self::Accept),
            3 => Ok(Self::Close),
            4 => Ok(Self::Dns),
            5 => Ok(Self::ProcessStart),
            6 => Ok(Self::ProcessExit),
            7 => Ok(Self::FileOpen),
            8 => Ok(Self::FileDelete),
            9 => Ok(Self::FileClose),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawEventHeader {
    pub event_type: EventType,
    pub timestamp_ns: u64,

    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,

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

impl TryFrom<u8> for RawProtocol {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(()),
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PendingConnect {
    pub header: RawEventHeader,
    pub protocol: RawProtocol,
    pub tid: u32,
    pub src_port: u16,
    pub dst_port: u16,

    pub ip_version: IpVersion,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
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
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawProcessExitEvent {
    pub header: RawEventHeader,
    pub exit_code: i32, // convert this back - (code << 8) & 0xff
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileOpenEvent {
    pub header: RawEventHeader,

    pub flags: u32,

    pub path: [u8; 256],
}

// #[repr(C)]
// #[derive(Debug, Clone, Copy)]
// pub struct rawfiledeleteevent {
//     pub header: raweventheader,

//     pub path: [u8; 256],
// }

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileCloseEvent {
    pub header: RawEventHeader,
    pub path: [u8; 256],
}
