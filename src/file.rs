#![allow(non_snake_case)]
use crate::error::*;
use crate::{
    Bpfx,
    common::{EventHeader, ProcessId},
    core::{Subscription, attach_file_probe},
};
use bpfx_common::raw::{
    FILE_BLK, FILE_CHR, FILE_DIR, FILE_FIFO, FILE_LNK, FILE_REG, FILE_SOCK, FileModeFilter,
    FilterKey, O_ACCMODE, O_APPEND, O_ASYNC, O_CLOEXEC, O_CREAT, O_DIRECT, O_DIRECTORY, O_DSYNC,
    O_EXCL, O_NOATIME, O_NOCTTY, O_NOFOLLOW, O_NONBLOCK, O_PATH, O_RDONLY, O_RDWR, O_SYNC,
    O_TMPFILE, O_TRUNC, O_WRONLY,
};
use core::fmt;
use futures::Stream;
use std::fmt::Display;
use std::path::Path;
use std::{
    ops::{BitOr, BitOrAssign},
    time::Duration,
};
use tokio::sync::mpsc::Sender;

/// Provides access to the raw open flags associated with a file.
///
/// Implementors expose the flags passed when the file was opened, allowing
/// callers to determine the file's access mode and inspect individual
/// [`O_*`](https://man7.org/linux/man-pages/man2/open.2.html) flags.
///
/// The default methods interpret the flags using the Linux `open(2)`
/// semantics.
///
/// # Access mode
///
/// [`O_ACCMODE`] contains the access-mode bits. The three supported access
/// modes are:
///
/// - [`O_RDONLY`] — open for reading only.
/// - [`O_WRONLY`] — open for writing only.
/// - [`O_RDWR`] — open for both reading and writing.
///
/// [`O_ACCMODE`]: https://man7.org/linux/man-pages/man2/open.2.html
/// [`O_RDONLY`]: https://man7.org/linux/man-pages/man2/open.2.html
/// [`O_WRONLY`]: https://man7.org/linux/man-pages/man2/open.2.html
/// [`O_RDWR`]: https://man7.org/linux/man-pages/man2/open.2.html
pub trait FileInfo {
    /// Returns the raw flags associated with the file.
    ///
    /// The returned value contains both the access mode (`O_RDONLY`,
    /// `O_WRONLY`, or `O_RDWR`) and any additional `O_*` status flags that
    /// were specified when the file was opened.
    fn flags_raw(&self) -> u32;

    /// Returns `true` if the file was opened for reading.
    ///
    /// This returns `true` for both `O_RDONLY` and `O_RDWR`.
    fn is_read(&self) -> bool {
        matches!(self.flags_raw() & O_ACCMODE, O_RDONLY | O_RDWR)
    }

    /// Returns `true` if the file was opened for writing.
    ///
    /// This returns `true` for both `O_WRONLY` and `O_RDWR`.
    fn is_write(&self) -> bool {
        matches!(self.flags_raw() & O_ACCMODE, O_WRONLY | O_RDWR)
    }

    fn has_flag(&self, flag: u32) -> bool {
        self.flags_raw() & flag != 0
    }

    /// Returns the file's open flags as a human-readable, pipe-separated string.
    ///
    /// The access mode is reported first, followed by any supported status
    /// flags. For example:
    ///
    /// ```text
    /// WRONLY|APPEND|CLOEXEC
    /// ```
    ///
    /// If no recognized flags are present, an empty string is returned.
    fn flags(&self) -> String {
        let flags = self.flags_raw();
        let mut out = Vec::new();

        match flags & O_ACCMODE {
            O_RDONLY => out.push("RDONLY"),
            O_WRONLY => out.push("WRONLY"),
            O_RDWR => out.push("RDWR"),
            _ => {}
        }

        macro_rules! push_flag {
            ($flag:ident) => {
                if flags & $flag != 0 {
                    out.push(stringify!($flag).trim_start_matches("O_"));
                }
            };
        }

        push_flag!(O_APPEND);
        push_flag!(O_ASYNC);
        push_flag!(O_CLOEXEC);
        push_flag!(O_CREAT);
        push_flag!(O_DIRECT);
        push_flag!(O_DIRECTORY);
        push_flag!(O_DSYNC);
        push_flag!(O_EXCL);
        push_flag!(O_NOATIME);
        push_flag!(O_NOCTTY);
        push_flag!(O_NOFOLLOW);
        push_flag!(O_NONBLOCK);
        push_flag!(O_PATH);
        push_flag!(O_SYNC);
        push_flag!(O_TRUNC);

        if flags & O_TMPFILE == O_TMPFILE {
            out.push("TMPFILE");
        }

        out.join("|")
    }
}

macro_rules! impl_file_info {
    ($t:ty) => {
        impl FileInfo for $t {
            fn flags_raw(&self) -> u32 {
                self.flags
            }
        }
    };
}

/// Describes the type of a filesystem object.
///
/// `FileType` represents the common Unix filesystem object types supported
/// by bpfx. It can be derived from a [`FileModeFilter`] and converted to the
/// corresponding Unix file-type mode bits.
///
/// # Variants
///
/// - [`FileType::Regular`] — a regular file.
/// - [`FileType::Directory`] — a directory.
/// - [`FileType::CharDevice`] — a character device.
/// - [`FileType::BlockDevice`] — a block device.
/// - [`FileType::Fifo`] — a named pipe (FIFO).
/// - [`FileType::Symlink`] — a symbolic link.
/// - [`FileType::Socket`] — a Unix or network socket.
/// - [`FileType::Unknown`] — an unrecognized or unsupported file type.

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub enum FileType {
    /// A regular file.
    Regular,

    /// A directory.
    Directory,

    /// A character device.
    CharDevice,

    /// A block device.
    BlockDevice,

    /// A named pipe (FIFO).
    Fifo,

    /// A symbolic link.
    Symlink,

    /// A socket.
    Socket,

    /// An unknown or unsupported filesystem object type.
    Unknown,
}

impl From<FileModeFilter> for FileType {
    /// Converts a [`FileModeFilter`] into its corresponding [`FileType`].
    ///
    /// Any file mode not recognized by the conversion is mapped to
    /// [`FileType::Unknown`].
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

impl FileType {
    /// Returns the Unix file-type mode bits corresponding to this file type.
    ///
    /// The returned value contains the `S_IF*` portion of a Unix file mode
    /// and can be combined with the permission bits of a mode value.
    ///
    /// # Returns
    ///
    /// | File type | Mode bits |
    /// |---|---:|
    /// | [`FileType::Regular`] | `0o100000` |
    /// | [`FileType::Directory`] | `0o040000` |
    /// | [`FileType::CharDevice`] | `0o020000` |
    /// | [`FileType::BlockDevice`] | `0o060000` |
    /// | [`FileType::Fifo`] | `0o010000` |
    /// | [`FileType::Symlink`] | `0o120000` |
    /// | [`FileType::Socket`] | `0o140000` |
    /// | [`FileType::Unknown`] | `0` |
    pub const fn mode_bits(self) -> u32 {
        match self {
            Self::Regular => 0o100000,
            Self::Directory => 0o040000,
            Self::CharDevice => 0o020000,
            Self::BlockDevice => 0o060000,
            Self::Fifo => 0o010000,
            Self::Symlink => 0o120000,
            Self::Socket => 0o140000,
            Self::Unknown => 0,
        }
    }
}

impl From<FileType> for u32 {
    /// Converts a [`FileType`] into its Unix file-type mode bits.
    fn from(value: FileType) -> Self {
        value.mode_bits()
    }
}

/// Emitted when the kernel completes opening a file.
/// Generated from the `vfs_open` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a file open operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub file_path: String,
    pub file_type: FileType,
    pub inode: u64,
    pub retval: i32,
    pub flags: u32,
}

impl Display for FileOpenEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} OPEN {} -> {}",
            self.header, self.file_path, self.retval,
        )
    }
}

impl_file_info!(FileOpenEvent);

impl FileOpenEvent {
    pub fn file_name(&self) -> &str {
        Path::new(&self.file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }

    pub fn file_path(&self) -> &str {
        self.file_path.as_str()
    }
}

/// Emitted when the kernel closes an open file.
/// Generated from the `filp_close` fexit hook.
/// This event is emitted immediately after the kernel completes the file
/// close operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct FileCloseEvent {
    pub header: EventHeader,
    pub file_path: String,
    pub file_type: FileType,
    pub inode: u64,
    pub retval: i32,
    pub flags: u32,
}

impl Display for FileCloseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} CLOSE {} ({})",
            self.header, self.file_path, self.retval
        )
    }
}

impl_file_info!(FileCloseEvent);

impl FileCloseEvent {
    pub fn file_name(&self) -> &str {
        Path::new(&self.file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }

    pub fn file_path(&self) -> &str {
        self.file_path.as_str()
    }
}

/// Emitted when the kernel completes a file read operation.
/// Generated from the `vfs_read` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a read request for a file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct FileReadEvent {
    pub header: EventHeader,
    pub file_path: String,
    pub file_type: FileType,
    pub inode: u64,
    pub retval: isize,
    pub flags: u32,
}

impl_file_info!(FileReadEvent);

impl FileReadEvent {
    pub fn file_name(&self) -> &str {
        Path::new(&self.file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }

    pub fn file_path(&self) -> &str {
        self.file_path.as_str()
    }
}

impl Display for FileReadEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} READ {} ({})",
            self.header, self.file_path, self.retval
        )
    }
}

/// Emitted when the kernel completes a file write operation.
/// Generated from the `vfs_write` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a write request for a file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct FileWriteEvent {
    pub header: EventHeader,
    pub file_path: String,
    pub file_type: FileType,
    pub inode: u64,
    pub retval: isize,
    pub flags: u32,
}

impl_file_info!(FileWriteEvent);

impl FileWriteEvent {
    pub fn file_name(&self) -> &str {
        Path::new(&self.file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("")
    }

    pub fn file_path(&self) -> &str {
        self.file_path.as_str()
    }
}

impl Display for FileWriteEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} WRITE {} ({})",
            self.header, self.file_path, self.retval
        )
    }
}

/// Emitted when the kernel unlinks a file from the filesystem.
/// Generated from the `vfs_unlink` fexit hook.
/// This event is emitted immediately after the kernel removes a directory
/// entry for a file.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
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
/// Generated using the `vfs_rename` fentry and fexit hooks to capture both
/// the operation metadata and its return value.
/// This event is emitted after the kernel completes the rename operation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct FileRenameEvent {
    pub header: EventHeader,
    pub old_filename: String,
    pub new_filename: String,
    pub file_type: FileType,
    pub flags: u32,
    pub retval: i32,
}

impl_file_info!(FileRenameEvent);

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
#[derive(Debug, Clone, PartialEq, PartialOrd, Eq, Ord, Hash)]
pub enum FileEvent {
    Open(FileOpenEvent),
    Read(FileReadEvent),
    Close(FileCloseEvent),
    Write(FileWriteEvent),
    Delete(FileDeleteEvent),
    Rename(FileRenameEvent),
}

/// Identifies a file event for deduplication.
///
/// The key contains only the fields that are relevant for determining whether
/// two file events should be considered equivalent by the event deduplication
/// logic.
///
/// Different event types use different identifying fields:
///
/// - [`FileEventKey::Read`] uses the inode and return value.
/// - [`FileEventKey::Write`] uses the inode and return value.
/// - [`FileEventKey::Open`] uses the inode and open flags.
/// - [`FileEventKey::Close`] uses the inode.
/// - [`FileEventKey::Rename`] uses the return value.
/// - [`FileEventKey::Delete`] uses the return value.
///
/// This type implements ordering and hashing so it can be used as a key in
/// collections such as [`HashMap`] and [`HashSet`].
///
/// [`HashMap`]: std::collections::HashMap
/// [`HashSet`]: std::collections::HashSet
#[derive(Hash, Eq, PartialEq, PartialOrd, Ord)]
pub enum FileEventKey {
    Read { inode: u64, retval: isize },

    Write { inode: u64, retval: isize },

    Open { inode: u64, flags: u32 },

    Close { inode: u64, retval: i32 },

    Rename { retval: i32 },

    Delete { retval: i32 },
}

impl FileEvent {
    /// Returns the deduplication key for this event.
    ///
    /// The returned key contains the fields used to determine whether this
    /// event is equivalent to another event for deduplication purposes.
    pub fn dedup_key(&self) -> FileEventKey {
        match self {
            FileEvent::Read(e) => FileEventKey::Read {
                inode: e.inode,
                retval: e.retval,
            },

            FileEvent::Open(e) => FileEventKey::Open {
                inode: e.inode,
                flags: e.flags,
            },

            FileEvent::Write(e) => FileEventKey::Write {
                inode: e.inode,
                retval: e.retval,
            },

            FileEvent::Close(e) => FileEventKey::Close {
                inode: e.inode,
                retval: e.retval,
            },

            FileEvent::Rename(e) => FileEventKey::Rename { retval: e.retval },

            FileEvent::Delete(e) => FileEventKey::Delete { retval: e.retval },
        }
    }

    /// Returns the [`FileMask`] corresponding to this event.
    ///
    /// The mask can be used to classify the event and compare it against
    /// file-event filters.
    pub fn event_type(&self) -> FileMask {
        match self {
            FileEvent::Open(_) => FileMask::OPEN,
            FileEvent::Close(_) => FileMask::CLOSE,
            FileEvent::Read(_) => FileMask::READ,
            FileEvent::Write(_) => FileMask::WRITE,
            FileEvent::Rename(_) => FileMask::RENAME,
            FileEvent::Delete(_) => FileMask::DELETE,
        }
    }

    /// Returns the common event header.
    ///
    /// The header contains metadata shared by all file events, such as the
    /// process identifier, timestamp, and kernel-thread information.
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

    /// Returns the process associated with this event.
    pub fn process(&self) -> ProcessId {
        self.header().process()
    }

    /// Returns the timestamp at which the event occurred.
    pub fn timestamp(&self) -> Duration {
        self.header().timestamp()
    }

    /// Returns `true` if the event originated from a kernel thread.
    pub fn is_kernel_thread(&self) -> bool {
        self.header().is_kernel_thread()
    }

    /// Returns the type of filesystem object associated with this event.
    pub fn file_type(&self) -> &FileType {
        match self {
            Self::Open(e) => &e.file_type,
            Self::Read(e) => &e.file_type,
            Self::Close(e) => &e.file_type,
            Self::Write(e) => &e.file_type,
            Self::Delete(e) => &e.file_type,
            Self::Rename(e) => &e.file_type,
        }
    }

    /// Returns the full path associated with the event, when available.
    ///
    /// Rename and delete events do not expose a file path through this
    /// accessor.
    pub fn file_path(&self) -> Option<&str> {
        match self {
            Self::Open(e) => Some(&e.file_path()),
            Self::Read(e) => Some(&e.file_path()),
            Self::Close(e) => Some(&e.file_path()),
            Self::Write(e) => Some(&e.file_path()),
            _ => None,
        }
    }

    /// Returns the file name associated with the event, when available.
    ///
    /// Rename and delete events do not expose a file name through this
    /// accessor.
    pub fn file_name(&self) -> Option<&str> {
        match self {
            Self::Open(e) => Some(e.file_name()),
            Self::Read(e) => Some(e.file_name()),
            Self::Close(e) => Some(e.file_name()),
            Self::Write(e) => Some(e.file_name()),
            _ => None,
        }
    }

    /// Returns the previous filename for a rename event.
    ///
    /// Returns `None` for all event types other than [`FileEvent::Rename`].
    pub fn old_filename(&self) -> Option<&str> {
        match self {
            Self::Rename(e) => Some(&e.old_filename),
            _ => None,
        }
    }

    /// Returns the new filename for a rename event.
    ///
    /// Returns `None` for all event types other than [`FileEvent::Rename`].
    pub fn new_filename(&self) -> Option<&str> {
        match self {
            Self::Rename(e) => Some(&e.new_filename),
            _ => None,
        }
    }

    /// Returns the return value of the underlying file operation.
    ///
    /// The return value follows the convention of the corresponding
    /// filesystem operation: non-negative values indicate success, while
    /// negative values indicate failure.
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

    /// Returns `true` if the underlying operation succeeded.
    ///
    /// An operation is considered successful when its return value is
    /// non-negative.
    pub fn succeeded(&self) -> bool {
        self.retval() >= 0
    }

    /// Returns `true` if the underlying operation failed.
    ///
    /// This is equivalent to `!self.succeeded()`.
    pub fn failed(&self) -> bool {
        !self.succeeded()
    }

    /// Returns the inode associated with the event, when available.
    ///
    /// Inode information is available for open, read, close, and write
    /// events. Rename and delete events return `None`.
    pub fn inode(&self) -> Option<u64> {
        match self {
            Self::Open(e) => Some(e.inode),
            Self::Read(e) => Some(e.inode),
            Self::Close(e) => Some(e.inode),
            Self::Write(e) => Some(e.inode),
            Self::Delete(_) => None,
            Self::Rename(_) => None,
        }
    }
}

impl BitOr for FileFilter {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self {
            filter: self.filter,
            file_mode: self.file_mode,
            event_type: self.event_type | rhs.event_type,
        }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
///     filter: FilterKey::default()
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
/// A registration owns the [`FileFilter`] used to configure the attached
/// probes and the channel through which matching [`FileEvent`]s are
/// delivered to the associated [`PollFile`] stream.
#[derive(Debug, Clone)]
pub(crate) struct FileRegister {
    pub filter: FileFilter,
    pub tx: Sender<FileEvent>,
}

impl Subscription for FileFilter {
    type Event = FileEvent;
    type Stream = PollFile;

    /// Registers the file-event probes and creates a stream for matching
    /// events.
    ///
    /// The subscription creates a bounded channel using the configured
    /// channel capacity, attaches the eBPF probes corresponding to the
    /// filter, and stores the registration in the [`Bpfx`] runtime.
    ///
    /// The returned [`PollFile`] receives events produced by the registered
    /// file-event probes.
    fn subscribe(self, bpfx: &mut Bpfx) -> Result<Self::Stream> {
        let (tx, rx) = tokio::sync::mpsc::channel(bpfx.config.channel_capacity);

        let reg = FileRegister { filter: self, tx };

        attach_file_probe(&reg.filter, &mut bpfx.bpf, &bpfx.btf)?;

        bpfx.file = Some(reg);

        Ok(PollFile { rx })
    }
}

impl FileFilter {
    /// Subscribes to file open events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const OPEN: Self = Self {
        event_type: FileMask::OPEN,
        file_mode: FileTypeFilter::ALL,
        filter: FilterKey::None,
    };

    /// Subscribes to file close events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const CLOSE: Self = Self {
        event_type: FileMask::CLOSE,
        file_mode: FileTypeFilter::ALL,
        filter: FilterKey::None,
    };

    /// Subscribes to file read events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const READ: Self = Self {
        event_type: FileMask::READ,
        file_mode: FileTypeFilter::ALL,
        filter: FilterKey::None,
    };

    /// Subscribes to file write events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const WRITE: Self = Self {
        event_type: FileMask::WRITE,
        file_mode: FileTypeFilter::ALL,
        filter: FilterKey::None,
    };

    /// Subscribes to file deletion events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const DELETE: Self = Self {
        event_type: FileMask::DELETE,
        file_mode: FileTypeFilter::ALL,
        filter: FilterKey::None,
    };

    /// Subscribes to file rename events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const RENAME: Self = Self {
        event_type: FileMask::RENAME,
        file_mode: FileTypeFilter::ALL,
        filter: FilterKey::None,
    };

    /// Subscribes to all supported file events.
    ///
    /// No additional file-type or key filtering is applied.
    pub const ALL: Self = Self {
        event_type: FileMask::ALL,
        file_mode: FileTypeFilter::ALL,
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
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
        Self::ALL
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
