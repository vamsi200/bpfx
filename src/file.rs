#![allow(unused)]
#![allow(non_snake_case)]
use core::fmt;
use std::{
    ops::{BitOr, BitOrAssign},
    time::Duration,
};

use crate::events::{EventHeader, ProcessId};
use bpfx_common::raw::FileModeFilter;
use futures::Stream;

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    Regular,
    Directory,
    CharDevice,
    BlockDevice,
    Fifo,
    Symlink,
    Socket,
    Unknown,
}

impl From<FileModeFilter> for FileType {
    fn from(mode: FileModeFilter) -> Self {
        const S_IFMT: u16 = 0o170000;

        match mode.file_types & S_IFMT {
            S_IFREG => Self::Regular,
            S_IFDIR => Self::Directory,
            S_IFCHR => Self::CharDevice,
            S_IFBLK => Self::BlockDevice,
            S_IFIFO => Self::Fifo,
            S_IFLNK => Self::Symlink,
            S_IFSOCK => Self::Socket,
            _ => Self::Unknown,
        }
    }
}

/// Emitted when the kernel completes opening a file.
/// Generated from the `vfs_open` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a file open operation.
#[derive(Debug, Clone)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub filename: String,
    pub file_type: FileType,
    pub retval: i32,
}

/// Emitted when the kernel closes an open file.
/// Generated from the `filp_close` fexit hook.
/// This event is emitted immediately after the kernel completes the file
/// close operation.
#[derive(Debug, Clone)]
pub struct FileCloseEvent {
    pub header: EventHeader,
    pub filename: String,
    pub file_type: FileType,
    pub retval: i32,
}

/// Emitted when the kernel completes a file read operation.
/// Generated from the `vfs_read` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a read request for a file.
#[derive(Debug, Clone)]
pub struct FileReadEvent {
    pub header: EventHeader,
    pub filename: String,
    pub file_type: FileType,
    pub retval: isize,
}

/// Emitted when the kernel completes a file write operation.
/// Generated from the `vfs_write` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a write request for a file.
#[derive(Debug, Clone)]
pub struct FileWriteEvent {
    pub header: EventHeader,
    pub filename: String,
    pub file_type: FileType,
    pub retval: isize,
}

/// Emitted when the kernel unlinks a file from the filesystem.
/// Generated from the `vfs_unlink` fexit hook.
/// This event is emitted immediately after the kernel removes a directory
/// entry for a file.
#[derive(Debug, Clone)]
pub struct FileDeleteEvent {
    pub header: EventHeader,
    pub filename: String,
    pub file_type: FileType,
    pub retval: i32,
}

/// Emitted when the kernel renames or moves a file.
/// Generated from the `vfs_rename` fentry hook.
/// This event is emitted immediately after the kernel performs the
/// rename operation.
#[derive(Debug, Clone)]
pub struct FileRenameEvent {
    pub header: EventHeader,
    pub old_filename: String,
    pub new_filename: String,
    pub file_type: FileType,
    pub retval: i32,
}

#[derive(Debug, Clone)]
pub enum FileEvent {
    Open(FileOpenEvent),
    Read(FileReadEvent),
    Close(FileCloseEvent),
    Write(FileWriteEvent),
    Delete(FileDeleteEvent),
    Rename(FileRenameEvent),
}

impl FileEvent {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::Open(e) => &e.header,
            Self::Read(e) => &e.header,
            Self::Close(e) => &e.header,
            Self::Write(e) => &e.header,
            Self::Delete(e) => &e.header,
            Self::Rename(e) => &e.header,
        }
    }

    pub fn process(&self) -> ProcessId {
        self.header().process()
    }

    pub fn timestamp(&self) -> Duration {
        self.header().timestamp()
    }

    pub fn is_kernel_thread(&self) -> bool {
        self.header().is_kernel_thread()
    }

    pub fn file_type(&self) -> FileType {
        match self {
            Self::Open(e) => e.file_type,
            Self::Read(e) => e.file_type,
            Self::Close(e) => e.file_type,
            Self::Write(e) => e.file_type,
            Self::Delete(e) => e.file_type,
            Self::Rename(e) => e.file_type,
        }
    }

    pub fn filename(&self) -> Option<&str> {
        match self {
            Self::Open(e) => Some(&e.filename),
            Self::Read(e) => Some(&e.filename),
            Self::Close(e) => Some(&e.filename),
            Self::Write(e) => Some(&e.filename),
            Self::Delete(e) => Some(&e.filename),
            Self::Rename(_) => None,
        }
    }

    pub fn old_filename(&self) -> Option<&str> {
        match self {
            Self::Rename(e) => Some(&e.old_filename),
            _ => None,
        }
    }

    pub fn new_filename(&self) -> Option<&str> {
        match self {
            Self::Rename(e) => Some(&e.new_filename),
            _ => None,
        }
    }

    pub fn retval(&self) -> isize {
        match self {
            Self::Open(e) => e.retval as isize,
            Self::Read(e) => e.retval,
            Self::Close(e) => e.retval as isize,
            Self::Write(e) => e.retval,
            Self::Delete(e) => e.retval as isize,
            Self::Rename(e) => e.retval as isize,
        }
    }

    pub fn succeeded(&self) -> bool {
        self.retval() >= 0
    }

    pub fn failed(&self) -> bool {
        !self.succeeded()
    }
}

pub struct PollFile {
    pub rx: tokio::sync::mpsc::Receiver<FileEvent>,
}

impl Stream for PollFile {
    type Item = FileEvent;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pf = self.get_mut();
        pf.rx.poll_recv(cx)
    }
}

#[derive(Debug)]
pub struct FileEventMask(u8);

impl FileEventMask {
    pub const OPEN: Self = Self(1 << 0);
    pub const CLOSE: Self = Self(1 << 1);
    pub const READ: Self = Self(1 << 2);
    pub const WRITE: Self = Self(1 << 3);
    pub const DELETE: Self = Self(1 << 4);
    pub const RENAME: Self = Self(1 << 5);

    pub const ALL: Self = Self(
        Self::OPEN.0
            | Self::CLOSE.0
            | Self::READ.0
            | Self::WRITE.0
            | Self::DELETE.0
            | Self::RENAME.0,
    );

    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for FileEventMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FileEventMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug)]
pub struct FileFilter {
    pub event_type: FileEventMask,
    pub file_mode: UserFileFilter,
}

impl Default for FileFilter {
    fn default() -> Self {
        Self {
            event_type: FileEventMask::ALL,
            file_mode: UserFileFilter::default(),
        }
    }
}

impl FileFilter {
    pub const OPEN: Self = Self {
        event_type: FileEventMask::OPEN,
        file_mode: UserFileFilter::FILE_REG,
    };

    pub const CLOSE: Self = Self {
        event_type: FileEventMask::CLOSE,
        file_mode: UserFileFilter::FILE_REG,
    };

    pub const READ: Self = Self {
        event_type: FileEventMask::READ,
        file_mode: UserFileFilter::FILE_REG,
    };

    pub const WRITE: Self = Self {
        event_type: FileEventMask::WRITE,
        file_mode: UserFileFilter::FILE_REG,
    };

    pub const DELETE: Self = Self {
        event_type: FileEventMask::DELETE,
        file_mode: UserFileFilter::FILE_REG,
    };

    pub const RENAME: Self = Self {
        event_type: FileEventMask::RENAME,
        file_mode: UserFileFilter::FILE_REG,
    };

    pub const ALL: Self = Self {
        event_type: FileEventMask::ALL,
        file_mode: UserFileFilter::FILE_REG,
    };
}

#[derive(Debug, Clone)]
pub struct UserFileFilter(pub FileModeFilter);

impl UserFileFilter {
    pub const FILE_REG: Self = Self(FileModeFilter { file_types: 1 << 0 });
    pub const FILE_DIR: Self = Self(FileModeFilter { file_types: 1 << 1 });
    pub const FILE_CHR: Self = Self(FileModeFilter { file_types: 1 << 2 });
    pub const FILE_BLK: Self = Self(FileModeFilter { file_types: 1 << 3 });
    pub const FILE_FIFO: Self = Self(FileModeFilter { file_types: 1 << 4 });
    pub const FILE_LNK: Self = Self(FileModeFilter { file_types: 1 << 5 });
    pub const FILE_SOCK: Self = Self(FileModeFilter { file_types: 1 << 6 });

    pub const ALL: Self = Self(FileModeFilter {
        file_types: Self::FILE_REG.0.file_types
            | Self::FILE_DIR.0.file_types
            | Self::FILE_CHR.0.file_types
            | Self::FILE_BLK.0.file_types
            | Self::FILE_FIFO.0.file_types
            | Self::FILE_LNK.0.file_types
            | Self::FILE_SOCK.0.file_types,
    });
}

impl Default for UserFileFilter {
    fn default() -> Self {
        Self::FILE_REG
    }
}

impl BitOr for UserFileFilter {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(FileModeFilter {
            file_types: self.0.file_types | rhs.0.file_types,
        })
    }
}

impl BitOrAssign for UserFileFilter {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0.file_types |= rhs.0.file_types;
    }
}

impl From<UserFileFilter> for FileModeFilter {
    fn from(value: UserFileFilter) -> Self {
        value.0
    }
}
