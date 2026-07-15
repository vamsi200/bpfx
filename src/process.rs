#![allow(unused)]
use crate::events::{EventHeader, ProcessId};
use futures::Stream;
use std::{
    ops::{BitOr, BitOrAssign},
    time::Duration,
};

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

/// Emitted when the kernel creates a new process.
/// Generated from the `sched_process_fork` tracepoint.
/// This event is emitted immediately after a new process has been created
/// by the kernel.
#[derive(Debug, Clone)]
pub struct ProcessForkEvent {
    pub parent: EventHeader,
    pub child_pid: u32,
    pub child_comm: String,
}

#[derive(Debug)]
pub enum ProcessEvent {
    Start(ProcessStartEvent),
    Fork(ProcessForkEvent),
    Exit(ProcessExitEvent),
}

impl ProcessEvent {
    pub fn header(&self) -> &EventHeader {
        match self {
            Self::Start(e) => &e.header,
            Self::Fork(e) => &e.parent,
            Self::Exit(e) => &e.header,
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

    pub fn is_start(&self) -> bool {
        matches!(self, Self::Start(_))
    }

    pub fn is_fork(&self) -> bool {
        matches!(self, Self::Fork(_))
    }

    pub fn is_exit(&self) -> bool {
        matches!(self, Self::Exit(_))
    }
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
pub struct ProcessMask(u8);

impl ProcessMask {
    pub const START: Self = Self(1 << 0);
    pub const FORK: Self = Self(1 << 1);
    pub const EXIT: Self = Self(1 << 2);

    pub const ALL: Self = Self(Self::START.0 | Self::FORK.0 | Self::EXIT.0);

    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for ProcessMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ProcessMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug)]
pub struct ProcessFilter {
    pub mask: ProcessMask,
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            mask: ProcessMask::ALL,
        }
    }
}

impl ProcessFilter {
    pub const START: Self = Self {
        mask: ProcessMask::START,
    };

    pub const FORK: Self = Self {
        mask: ProcessMask::FORK,
    };

    pub const EXIT: Self = Self {
        mask: ProcessMask::EXIT,
    };

    pub const ALL: Self = Self {
        mask: ProcessMask::ALL,
    };
}
