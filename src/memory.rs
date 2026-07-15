#![allow(unused)]
use std::{
    fmt::Debug,
    ops::{BitOr, BitOrAssign},
};

use futures::Stream;

use crate::events::EventHeader;

#[derive(Debug, Clone)]
pub struct MemoryMapEvent {
    pub header: EventHeader,
    pub address: u64,
    pub length: u64,
    pub protection: u32,
    pub flags: u32,
}

#[derive(Debug, Clone)]
pub struct MemoryUnmapEvent {
    pub header: EventHeader,
    pub address: u64,
    pub length: u64,
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
    pub event_type: MemoryMask,
}

impl Default for MemoryFilter {
    fn default() -> Self {
        Self {
            event_type: MemoryMask::ALL,
        }
    }
}

impl MemoryFilter {
    pub const ALL: Self = Self {
        event_type: MemoryMask::ALL,
    };

    pub const MMAP: Self = Self {
        event_type: MemoryMask::MMAP,
    };

    pub const UNMAP: Self = Self {
        event_type: MemoryMask::UNMAP,
    };
}
