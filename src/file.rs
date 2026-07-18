#![allow(non_snake_case)]
use crate::error::*;
use crate::{
    Bpfx,
    common::{EventHeader, ProcessId},
    core::{Subscription, attach_file_probe},
};
use bpfx_common::raw::{
    FILE_BLK, FILE_CHR, FILE_DIR, FILE_FIFO, FILE_LNK, FILE_REG, FILE_SOCK, FileModeFilter,
    FilterKey,
};
use core::fmt;
use futures::Stream;
use std::fmt::Display;
use std::{
    ops::{BitOr, BitOrAssign},
    time::Duration,
};
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        match mode.mode {
            FILE_REG => Self::Regular,
            FILE_DIR => Self::Directory,
            FILE_CHR => Self::CharDevice,
            FILE_BLK => Self::BlockDevice,
            FILE_FIFO => Self::Fifo,
            FILE_LNK => Self::Symlink,
            FILE_SOCK => Self::Socket,
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

impl Display for FileOpenEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} OPEN {} -> {}",
            self.header, self.filename, self.retval,
        )
    }
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

impl Display for FileCloseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} CLOSE {} ({})",
            self.header, self.filename, self.retval
        )
    }
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

impl Display for FileReadEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} READ {} ({})",
            self.header, self.filename, self.retval
        )
    }
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

impl Display for FileWriteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} WRITE {} ({})",
            self.header, self.filename, self.retval
        )
    }
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

impl Display for FileDeleteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} DELETE {} ({})",
            self.header, self.filename, self.retval
        )
    }
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

impl Display for FileRenameEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} RENAME ({}) => ({}) ({})",
            self.header, self.old_filename, self.new_filename, self.retval
        )
    }
}

/// A file system event.
///
/// This enum groups all file-related events emitted by bpfx, including file
/// opens, reads, writes, closes, deletions, and renames.
///
/// Use pattern matching or the provided helper methods to inspect the
/// underlying event.
///
/// This enum is marked as `non_exhaustive` and may gain additional variants
/// in future releases.
#[non_exhaustive]
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

/// A stream of file events.
///
/// Instances of this type are returned by [`Bpfx::subscribe`] when subscribing
/// with a [`FileFilter`].
///
/// Implements [`futures::Stream`], yielding [`FileEvent`].
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

/// Bitmask describing which file operations should generate events.
///
/// # Examples
///
/// ```rust
/// # use bpfx::file::FileMask;
/// let mask = FileMask::OPEN | FileMask::WRITE | FileMask::DELETE;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileMask(u8);

impl FileMask {
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

impl std::fmt::Display for FileMask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == FileMask::OPEN {
            write!(f, "OPEN")
        } else if *self == FileMask::READ {
            write!(f, "READ")
        } else if *self == FileMask::WRITE {
            write!(f, "WRITE")
        } else if *self == FileMask::RENAME {
            write!(f, "RENAME")
        } else if *self == FileMask::CLOSE {
            write!(f, "CLOSE")
        } else if *self == FileMask::DELETE {
            write!(f, "DELETE")
        } else {
            write!(f, "{:?}", self)
        }
    }
}

impl BitOr for FileMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for FileMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Configures which file events are delivered.
///
/// A `FileFilter` controls:
///
/// - which kinds of file operations are reported (`event_type`)
/// - which file types are monitored (`file_mode`)
/// - an optional process-based filter (`filter`)
///
/// # Examples
///
/// Monitor file opens and renames for regular files:
///
/// ```rust
/// # use bpfx::{FileFilter, FileMask, FileTypeFilter};
/// let filter = FileFilter {
///     event_type: FileMask::OPEN | FileMask::RENAME,
///     file_mode: FileTypeFilter::FILE_REG,
///     ..Default::default()
/// };
/// ```
#[derive(Debug)]
pub struct FileFilter {
    pub event_type: FileMask,
    pub file_mode: FileTypeFilter,
    pub filter: FilterKey,
}

impl Default for FileFilter {
    fn default() -> Self {
        Self {
            event_type: FileMask::ALL,
            file_mode: FileTypeFilter::default(),
            filter: FilterKey::None,
        }
    }
}

/// Internal registration state for a file event subscription.
///
/// Stores the active filter and the channel used to deliver events
/// to the corresponding event stream.
#[derive(Debug)]
pub(crate) struct FileRegister {
    pub filter: FileFilter,
    pub tx: Sender<FileEvent>,
}

impl Subscription for FileFilter {
    type Event = FileEvent;
    type Stream = PollFile;

    fn subscribe(self, bpfx: &mut Bpfx) -> Result<Self::Stream> {
        let (tx, rx) = tokio::sync::mpsc::channel(bpfx.config.channel_capacity);

        let reg = FileRegister { filter: self, tx };

        attach_file_probe(&reg.filter, &mut bpfx.bpf, &bpfx.btf)?;

        bpfx.file = Some(reg);

        Ok(PollFile { rx })
    }
}

impl FileFilter {
    pub const OPEN: Self = Self {
        event_type: FileMask::OPEN,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };

    pub const CLOSE: Self = Self {
        event_type: FileMask::CLOSE,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };

    pub const READ: Self = Self {
        event_type: FileMask::READ,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };

    pub const WRITE: Self = Self {
        event_type: FileMask::WRITE,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };

    pub const DELETE: Self = Self {
        event_type: FileMask::DELETE,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };

    pub const RENAME: Self = Self {
        event_type: FileMask::RENAME,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };

    pub const ALL: Self = Self {
        event_type: FileMask::ALL,
        file_mode: FileTypeFilter::FILE_REG,
        filter: FilterKey::None,
    };
}

/// Bitmask describing which file types are monitored.
///
/// By default, only regular files are monitored.
///
/// # Examples
///
/// Monitor both regular files and directories:
///
/// ```rust
/// # use bpfx::file::FileTypeFilter;
/// let types = FileTypeFilter::FILE_REG | UserFileFilter::FILE_DIR;
/// ```
#[derive(Debug, Clone)]
pub struct FileTypeFilter(pub FileModeFilter);

impl FileTypeFilter {
    /// Regular files.
    pub const FILE_REG: Self = Self(FileModeFilter { mode: 1 << 0 });
    /// Directories.
    pub const FILE_DIR: Self = Self(FileModeFilter { mode: 1 << 1 });
    /// Character devices.
    pub const FILE_CHR: Self = Self(FileModeFilter { mode: 1 << 2 });
    /// Block devices.
    pub const FILE_BLK: Self = Self(FileModeFilter { mode: 1 << 3 });
    /// FIFOs (named pipes).
    pub const FILE_FIFO: Self = Self(FileModeFilter { mode: 1 << 4 });
    /// Symbolic links.
    pub const FILE_LNK: Self = Self(FileModeFilter { mode: 1 << 5 });
    /// Unix domain sockets.
    pub const FILE_SOCK: Self = Self(FileModeFilter { mode: 1 << 6 });

    /// All file types.
    pub const ALL: Self = Self(FileModeFilter {
        mode: Self::FILE_REG.0.mode
            | Self::FILE_DIR.0.mode
            | Self::FILE_CHR.0.mode
            | Self::FILE_BLK.0.mode
            | Self::FILE_FIFO.0.mode
            | Self::FILE_LNK.0.mode
            | Self::FILE_SOCK.0.mode,
    });
}

impl Default for FileTypeFilter {
    fn default() -> Self {
        Self::FILE_REG
    }
}

impl BitOr for FileTypeFilter {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(FileModeFilter {
            mode: self.0.mode | rhs.0.mode,
        })
    }
}

impl BitOrAssign for FileTypeFilter {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0.mode |= rhs.0.mode;
    }
}

impl From<FileTypeFilter> for FileModeFilter {
    fn from(value: FileTypeFilter) -> Self {
        value.0
    }
}
