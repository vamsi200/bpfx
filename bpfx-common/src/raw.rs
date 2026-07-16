#![no_std]
#![allow(unused)]

use core::ops::{BitOr, BitOrAssign};
pub const TASK_COMM_LEN: usize = 16;
pub const DNS_NAME_MAX: usize = 256;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Connect = 1,
    Accept = 2,
    Close = 3,
    ProcessStart = 4,
    ProcessFork = 5,
    ProcessExit = 6,
    FileOpen = 7,
    FileRead = 8,
    FileClose = 9,
    FileWrite = 10,
    FileDelete = 11,
    FileRename = 12,
    Bind = 13,
    Listen = 14,
    MemoryMap = 15,
    MemoryUnMap = 16,
}

impl TryFrom<u8> for EventType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Connect),
            2 => Ok(Self::Accept),
            3 => Ok(Self::Close),
            4 => Ok(Self::ProcessStart),
            5 => Ok(Self::ProcessExit),
            6 => Ok(Self::FileOpen),
            7 => Ok(Self::FileClose),
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
    pub retval: Option<i32>,
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
    pub filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileCloseEvent {
    pub header: RawEventHeader,
    pub filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawProcessForkEvent {
    pub parent: RawEventHeader,
    pub child_pid: u32,
    // pub child_tid: u32, I think child_tid won't add much information at fork
    pub child_comm: [u8; TASK_COMM_LEN],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileReadEvent {
    pub header: RawEventHeader,
    pub filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: isize,
}

#[cfg(feature = "user")]
use aya::Pod;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FileModeFilter {
    pub file_types: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileModeFilter {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileWriteEvent {
    pub header: RawEventHeader,
    pub filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: isize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileDeleteEvent {
    pub header: RawEventHeader,
    pub filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileRenameEvent {
    pub header: RawEventHeader,
    pub old_filename: [u8; 256],
    pub new_filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawMemoryMapEvent {
    pub header: RawEventHeader,
    pub requested_address: usize,
    pub length: u64,
    pub protection: u32,
    pub flags: u32,
    pub mapped_address: usize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawMemoryUnmapEvent {
    pub header: RawEventHeader,
    pub requested_address: usize,
    pub length: u64,
    pub mapped_address: usize,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum FilterKey {
    None,
    Pid(u32),
    Tid(u32),
    Ppid(u32),
    Uid(u32),
    Gid(u32),
}

#[repr(u32)]
pub enum FilterOwner {
    Memory = 0,
    Process = 1,
    Network = 2,
    File = 3,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterKey {}
