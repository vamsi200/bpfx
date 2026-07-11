#![allow(unused)]
use std::ops::{BitOr, BitOrAssign};

use futures::Stream;

use crate::events::EventHeader;

/// Emitted after the kernel successfully executes a new program image for a process.
/// Generated from the `sched_process_exec` tracepoint.
/// This event is emitted after a successful `execve()`- family call, when the
/// process begins executing the new executable.
#[derive(Debug, Clone)]
pub struct ProcessStartEvent {
    pub header: EventHeader,
    pub filename: String,
}

/// Emitted when a process exits.
/// Generated from `do_group_exit()`.
/// The `exit_code` contains the raw kernel exit status.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub exit_code: i32,
}

impl ProcessExitEvent {
    pub fn status(&self) -> u8 {
        ((self.exit_code << 8) & 0xff) as u8
    }
}

#[derive(Debug)]
pub enum ProcessEvent {
    Start(ProcessStartEvent),
    Exit(ProcessExitEvent),
}

pub struct PollProcess {
    pub rx: tokio::sync::mpsc::Receiver<ProcessEvent>,
}

impl Stream for PollProcess {
    type Item = ProcessEvent;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pn = self.get_mut();
        pn.rx.poll_recv(cx)
    }
}

#[derive(Debug)]
pub struct ProcessEventMask(u8);

impl ProcessEventMask {
    pub const START: Self = Self(1 << 0);
    pub const EXIT: Self = Self(1 << 1);

    pub const ALL: Self = Self(Self::START.0 | Self::EXIT.0);

    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for ProcessEventMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ProcessEventMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug)]
pub struct ProcessFilter {
    pub event_type: ProcessEventMask,
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            event_type: ProcessEventMask::ALL,
        }
    }
}
