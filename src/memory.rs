#![allow(unused)]
use crate::events::{EventHeader, ProcessId};
use futures::Stream;
use std::{
    fmt::Debug,
    ops::{BitOr, BitOrAssign},
    time::Duration,
};

/// Emitted when the kernel completes a virtual memory mapping operation.
/// Generated from the `vm_mmap_pgoff` fexit hook.
/// This event is emitted immediately after the kernel finishes creating a
/// virtual memory mapping.
#[derive(Debug, Clone)]
pub struct MemoryMapEvent {
    pub header: EventHeader,
    pub requested_address: usize,
    pub length: u64,
    pub protection: u32,
    pub flags: u32,
    pub mapped_address: usize,
}

/// Emitted when the kernel completes a virtual memory unmapping operation.
/// Generated from the `__vm_munmap` fexit hook.
/// This event is emitted immediately after the kernel finishes removing a
/// virtual memory mapping.
#[derive(Debug, Clone)]
pub struct MemoryUnmapEvent {
    pub header: EventHeader,
    pub requested_address: usize,
    pub length: u64,
    pub mapped_address: usize,
}

pub struct PollMem {
    pub rx: tokio::sync::mpsc::Receiver<MemoryEvent>,
}

impl Stream for PollMem {
    type Item = MemoryEvent;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pm = self.get_mut();
        pm.rx.poll_recv(cx)
    }
}

#[derive(Debug)]
pub enum MemoryEvent {
    MemoryMap(MemoryMapEvent),
    MemoryUnMap(MemoryUnmapEvent),
}

impl MemoryEvent {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::MemoryMap(e) => &e.header,
            Self::MemoryUnMap(e) => &e.header,
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

    pub fn is_mmap(&self) -> bool {
        matches!(self, Self::MemoryMap(_))
    }

    pub fn is_unmap(&self) -> bool {
        matches!(self, Self::MemoryUnMap(_))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct MemoryMask(u8);

impl MemoryMask {
    pub const MMAP: Self = Self(1 << 0);
    pub const UNMAP: Self = Self(1 << 1);

    pub const ALL: Self = Self(Self::MMAP.0 | Self::UNMAP.0);

    pub fn contains(&self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for MemoryMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for MemoryMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0
    }
}

#[derive(Debug, Clone)]
pub struct MemoryFilter {
    pub mask: MemoryMask,
}

impl Default for MemoryFilter {
    fn default() -> Self {
        Self {
            mask: MemoryMask::ALL,
        }
    }
}

impl MemoryFilter {
    pub const ALL: Self = Self {
        mask: MemoryMask::ALL,
    };

    pub const MMAP: Self = Self {
        mask: MemoryMask::MMAP,
    };

    pub const UNMAP: Self = Self {
        mask: MemoryMask::UNMAP,
    };
}
