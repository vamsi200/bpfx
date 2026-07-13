#![allow(unused)]
use std::ops::{BitOr, BitOrAssign};

use bpfx_common::raw::FileModeFilter;
use futures::Stream;

use crate::events::EventHeader;

/// Emitted when a process attempts to open a file.
/// Generated from the `sys_enter_openat` tracepoint.
/// This event is emitted at the entry of the `openat()` system call,
/// before the kernel resolves the pathname or creates the file descriptor.
#[derive(Debug, Clone)]
pub struct FileOpenEvent {
    pub header: EventHeader,
    pub flags: u32,
    pub path: String,
}

/// Emitted when the kernel closes an open file.
/// Generated from the `filp_close` fentry hook.
/// This event is emitted immediately before the kernel completes the file
/// close operation.
#[derive(Debug, Clone)]
pub struct FileCloseEvent {
    pub header: EventHeader,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct FileReadEvent {
    pub header: EventHeader,
    pub filename: String,
}

#[derive(Debug, Clone)]
pub enum FileEvent {
    FileOpen(FileOpenEvent),
    FileRead(FileReadEvent),
    FileClose(FileCloseEvent),
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

    pub const ALL: Self = Self(Self::OPEN.0 | Self::CLOSE.0 | Self::READ.0);

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
    pub file_mode: Option<UserFileFilter>,
}

impl Default for FileFilter {
    fn default() -> Self {
        Self {
            event_type: FileEventMask::ALL,
            file_mode: Some(UserFileFilter::default()),
        }
    }
}

impl FileFilter {
    pub const OPEN: Self = Self {
        event_type: FileEventMask::OPEN,
        file_mode: None,
    };

    pub const CLOSE: Self = Self {
        event_type: FileEventMask::CLOSE,
        file_mode: None,
    };

    pub const READ: Self = Self {
        event_type: FileEventMask::READ,
        file_mode: None,
    };

    pub const ALL: Self = Self {
        event_type: FileEventMask::ALL,
        file_mode: Some(UserFileFilter::FILE_REG),
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
