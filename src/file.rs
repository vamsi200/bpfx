#![allow(unused)]
use std::ops::{BitOr, BitOrAssign};

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
pub enum FileEvent {
    FileOpen(FileOpenEvent),
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

    pub const ALL: Self = Self(Self::OPEN.0 | Self::CLOSE.0);

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
}

impl Default for FileFilter {
    fn default() -> Self {
        Self {
            event_type: FileEventMask::ALL,
        }
    }
}

impl FileFilter {
    pub const OPEN: Self = Self {
        event_type: FileEventMask::OPEN,
    };

    pub const CLOSE: Self = Self {
        event_type: FileEventMask::CLOSE,
    };

    pub const ALL: Self = Self {
        event_type: FileEventMask::ALL,
    };
}

// impl From<FileEventMask> for FileFilter {
//     fn from(value: FileEventMask) -> Self {
//         Self { event_type: value }
//     }
// }
