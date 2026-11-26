#![allow(unused)]
pub const TASK_COMM_LEN: usize = 16;
pub const DNS_NAME_MAX: usize = 256;

pub const FILE_REG: u16 = 1 << 0;
pub const FILE_DIR: u16 = 1 << 1;
pub const FILE_CHR: u16 = 1 << 2;
pub const FILE_BLK: u16 = 1 << 3;
pub const FILE_FIFO: u16 = 1 << 4;
pub const FILE_LNK: u16 = 1 << 5;
pub const FILE_SOCK: u16 = 1 << 6;

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_ACCMODE: u32 = 3;
pub const O_APPEND: u32 = 1024;
pub const O_ASYNC: u32 = 0x2000;
pub const O_CLOEXEC: u32 = 0x80000;
pub const O_CREAT: u32 = 64;
pub const O_DIRECT: u32 = 0x4000;
pub const O_DIRECTORY: u32 = 0x10000;
pub const O_DSYNC: u32 = 4096;
pub const O_EXCL: u32 = 128;
pub const O_NOATIME: u32 = 0o1000000;
pub const O_NOCTTY: u32 = 256;
pub const O_NOFOLLOW: u32 = 0x20000;
pub const O_NONBLOCK: u32 = 2048;
pub const O_PATH: u32 = 0o10000000;
pub const O_SYNC: u32 = 1052672;
pub const O_TRUNC: u32 = 512;
pub const O_TMPFILE: u32 = 0o20000000 | O_DIRECTORY;

#[non_exhaustive]
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum EventType {
    Connect = 1,
    Accept = 2,
    Close = 3,
    ProcessStart = 4,
    ProcessFork = 5,
    ProcessExit = 6,
    FileCreate = 7,
    FileOpen = 8,
    FileRead = 9,
    FileClose = 10,
    FileWrite = 11,
    FileDelete = 12,
    FileRename = 13,
    Mkdir = 14,
    Rmdir = 15,
    Bind = 16,
    Listen = 17,
    MemoryMap = 18,
    MemoryUnMap = 19,
    PendingFileRename = 20,
    Truncate = 21,
    FileSync = 22,
    FileChown = 23,
    FileChmod = 24,
    FileLink = 25,
    FileSymLink = 26,
    Send = 27,
    Receive = 28,
    TcpRetransmit = 29,
    TcpStateChange = 30,
}

impl TryFrom<u8> for EventType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Connect),
            2 => Ok(Self::Accept),
            3 => Ok(Self::Close),
            4 => Ok(Self::ProcessStart),
            5 => Ok(Self::ProcessFork),
            6 => Ok(Self::ProcessExit),
            7 => Ok(Self::FileCreate),
            8 => Ok(Self::FileOpen),
            9 => Ok(Self::FileRead),
            10 => Ok(Self::FileClose),
            11 => Ok(Self::FileWrite),
            12 => Ok(Self::FileDelete),
            13 => Ok(Self::FileRename),
            14 => Ok(Self::Mkdir),
            15 => Ok(Self::Rmdir),
            16 => Ok(Self::Bind),
            17 => Ok(Self::Listen),
            18 => Ok(Self::MemoryMap),
            19 => Ok(Self::MemoryUnMap),
            20 => Ok(Self::PendingFileRename),
            21 => Ok(Self::Truncate),
            22 => Ok(Self::FileSync),
            23 => Ok(Self::FileChown),
            24 => Ok(Self::FileChmod),
            25 => Ok(Self::FileLink),
            26 => Ok(Self::FileSymLink),
            27 => Ok(Self::Send),
            28 => Ok(Self::Receive),
            29 => Ok(Self::TcpRetransmit),
            30 => Ok(Self::TcpStateChange),
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
pub struct RawNetworkEndpoints {
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub ip_version: IpVersion,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSendEvent {
    pub header: RawEventHeader,
    pub protocol: RawProtocol,
    pub endpoints: RawNetworkEndpoints,
    pub requested_len: u64,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawReceiveEvent {
    pub header: RawEventHeader,
    pub protocol: RawProtocol,
    pub endpoints: RawNetworkEndpoints,
    pub requested_len: u64,
    pub flags: i32,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawTcpRetransmitEvent {
    pub header: RawEventHeader,
    pub endpoints: RawNetworkEndpoints,
    pub state: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawTcpStateChangeEvent {
    pub header: RawEventHeader,
    pub endpoints: RawNetworkEndpoints,
    pub old_state: i32,
    pub new_state: i32,
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
pub struct RawFilePath {
    pub filepath: [u8; 256],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileLinkEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub source_inode: u64,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileSymlinkEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub target: [u8; 256],
    pub inode: u64,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileChmodEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub inode: u64,
    pub requested_mode: u16,
    pub inode_mode: u16,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileChownEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub inode: u64,
    pub requested_uid: u32,
    pub requested_gid: u32,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileSyncEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub inode: u64,
    pub start: i64,
    pub end: i64,
    pub datasync: i32,
    pub retval: i32,
    pub mode: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileTruncateEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub inode: u64,
    pub requested_size: i64,
    pub mode: u16,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileCreateEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub file_mode: FileModeFilter,
    pub inode: u64,
    pub retval: isize,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawMkdirEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub inode: u64,
    pub mode: u16,
    pub retval: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RawRmdirEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub inode: u64,
    pub mode: u16,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileOpenEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub file_mode: FileModeFilter,
    pub inode: u64,
    pub retval: i32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileCloseEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub file_mode: FileModeFilter,
    pub inode: u64,
    pub retval: i32,
    pub flags: u32,
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
    pub file_path: [u8; 256],
    pub file_mode: FileModeFilter,
    pub inode: u64,
    pub retval: isize,
    pub flags: u32,
}

#[cfg(feature = "user")]
use aya::Pod;

/// Internal bitmask representation of selected file types.
///
/// This type is shared with the eBPF program and is not intended for
/// direct construction by users.
#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Copy)]
pub struct FileModeFilter {
    pub mode: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileModeFilter {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileWriteEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub file_mode: FileModeFilter,
    pub inode: u64,
    pub flags: u32,
    pub retval: isize,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileDeleteEvent {
    pub header: RawEventHeader,
    pub file_path: [u8; 256],
    pub file_mode: FileModeFilter,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct RawFileRtrEvent {
    pub header: RawEventHeader,
    pub retval: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawFileRenameEvent {
    pub header: RawEventHeader,
    pub old_filename: [u8; 256],
    pub new_filename: [u8; 256],
    pub file_mode: FileModeFilter,
    pub flags: u32,
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

/// Restricts events to a specific process or user.
///
///
/// # Examples
///
/// ```rust
/// # use bpfx::{file::FileFilter, FilterKey};
/// let filter = FileFilter {
///     filter: FilterKey::Pid(1234),
///     ..Default::default()
/// };
/// ```
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum FilterKey {
    /// Do not apply additional filtering.
    None,
    /// Match a specific string bytes
    Path([u8; 256]),
    /// Match a specific process ID.
    Pid(u32),
    /// Match a specific thread ID.
    Tid(u32),
    /// Match a specific parent process ID.
    Ppid(u32),
    /// Match a specific user ID.
    Uid(u32),
    /// Match a specific group ID.
    Gid(u32),
}

#[cfg(feature = "user")]
extern crate std;

#[cfg(feature = "user")]
impl FilterKey {
    pub fn path(path: impl AsRef<std::path::Path>) -> Result<Self, &'static str> {
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_ref().as_os_str().as_bytes();

        if bytes.len() >= 256 || bytes.contains(&0) {
            return Err("Invalid path");
        }

        let mut buf = [0u8; 256];
        buf[..bytes.len()].copy_from_slice(bytes);

        Ok(Self::Path(buf))
    }
}

#[non_exhaustive]
#[repr(u32)]
#[derive(PartialEq)]
pub enum FilterOwner {
    Memory = 0,
    Process = 1,
    Network = 2,
    File = 3,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FilterKey {}
