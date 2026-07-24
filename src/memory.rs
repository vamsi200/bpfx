use crate::error::*;
use crate::{
    Bpfx,
    common::{EventHeader, ProcessId},
    core::{Subscription, attach_mem_probe},
};
use bpfx_common::raw::FilterKey;
use core::fmt;
use futures::Stream;
use std::fmt::Display;
use std::{
    ops::{BitOr, BitOrAssign},
    time::Duration,
};
use tokio::sync::mpsc::Sender;

/// Emitted when the kernel completes a virtual memory mapping operation.
/// Generated from the `vm_mmap_pgoff` fexit hook.
/// This event is emitted immediately after the kernel finishes creating a
/// virtual memory mapping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct MemoryMapEvent {
    pub header: EventHeader,
    pub requested_address: usize,
    pub length: u64,
    pub protection: u32,
    pub flags: u32,
    pub mapped_address: usize,
}

impl Display for MemoryMapEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} MMAP addr={:#x} len={:#x} -> {:#x}",
            self.header, self.requested_address, self.length, self.mapped_address,
        )
    }
}

/// Emitted when the kernel completes a virtual memory unmapping operation.
/// Generated from the `__vm_munmap` fexit hook.
/// This event is emitted immediately after the kernel finishes removing a
/// virtual memory mapping.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(
    feature = "archive",
    derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)
)]
pub struct MemoryUnmapEvent {
    pub header: EventHeader,
    pub requested_address: usize,
    pub length: u64,
    pub mapped_address: usize,
}

impl Display for MemoryUnmapEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} MUNMAP addr={:#x} len={:#x}",
            self.header, self.requested_address, self.length,
        )
    }
}

/// A stream of memory events.
///
/// Instances of this type are returned by [`Bpfx::subscribe`] when subscribing
/// with a [`MemoryFilter`].
///
/// Implements [`futures::Stream`], yielding [`MemoryEvent`].
pub struct PollMem {
    rx: tokio::sync::mpsc::Receiver<MemoryEvent>,
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

/// A virtual memory event.
///
/// This enum groups virtual memory mapping and unmapping events emitted by
/// bpfx.
///
/// Use pattern matching or the provided helper methods to inspect the
/// underlying event.
///
/// This enum is marked as `non_exhaustive` and may gain additional variants
/// in future releases.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum MemoryEvent {
    MemoryMap(MemoryMapEvent),
    MemoryUnMap(MemoryUnmapEvent),
}

impl Display for MemoryEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MemoryMap(e) => e.fmt(f),
            Self::MemoryUnMap(e) => e.fmt(f),
        }
    }
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

/// Bitmask describing which memory events should generate notifications.
///
/// # Examples
///
/// ```rust
/// # use bpfx::memory::MemoryMask;
/// let mask = MemoryMask::MMAP | MemoryMask::UNMAP;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
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

/// Configures which memory events are delivered.
///
/// A `MemoryFilter` controls:
///
/// - which memory operations generate events (`mask`)
/// - an optional process-based filter (`filter`)
///
/// # Examples
///
/// Monitor only `mmap` events from a specific process:
///
/// ```rust
/// # use bpfx::{memory::{MemoryFilter, MemoryMask}, FilterKey};
/// let filter = MemoryFilter {
///     mask: MemoryMask::MMAP,
///     filter: FilterKey::Pid(1234),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct MemoryFilter {
    pub mask: MemoryMask,
    pub filter: FilterKey,
}

/// Internal registration state for a memory event subscription.
///
/// Stores the active filter and the channel used to deliver events
/// to the corresponding event stream.
#[derive(Debug)]
pub(crate) struct MemRegister {
    pub filter: MemoryFilter,
    pub tx: Sender<MemoryEvent>,
}

impl Subscription for MemoryFilter {
    type Event = MemoryEvent;
    type Stream = PollMem;

    fn subscribe(self, bpfx: &mut Bpfx) -> Result<Self::Stream> {
        let (tx, rx) = tokio::sync::mpsc::channel::<MemoryEvent>(bpfx.config.channel_capacity);
        let fr = MemRegister { filter: self, tx };
        attach_mem_probe(&fr.filter, &mut bpfx.bpf, &bpfx.btf)?;
        bpfx.mem = Some(fr);

        Ok(PollMem { rx })
    }
}

impl Default for MemoryFilter {
    fn default() -> Self {
        Self {
            mask: MemoryMask::ALL,
            filter: FilterKey::None,
        }
    }
}

impl MemoryFilter {
    pub const ALL: Self = Self {
        mask: MemoryMask::ALL,
        filter: FilterKey::None,
    };

    pub const MMAP: Self = Self {
        mask: MemoryMask::MMAP,
        filter: FilterKey::None,
    };

    pub const UNMAP: Self = Self {
        mask: MemoryMask::UNMAP,
        filter: FilterKey::None,
    };
}
