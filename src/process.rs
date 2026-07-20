use crate::error::*;
use crate::{
    Bpfx,
    common::{EventHeader, ProcessId},
    core::{Subscription, attach_process_probe},
};
use bpfx_common::raw::FilterKey;
use futures::Stream;
use std::fmt::Display;
use std::{
    ops::{BitOr, BitOrAssign},
    time::Duration,
};
use tokio::sync::mpsc::Sender;

/// Emitted after the kernel successfully executes a new program image for a process.
/// Generated from the `sched_process_exec` tracepoint.
/// This event is emitted after a successful `execve()`- family call, when the
/// process begins executing the new executable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessStartEvent {
    pub header: EventHeader,
    pub filename: String,
}

impl Display for ProcessStartEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} START {}", self.header, self.filename,)
    }
}

/// Emitted when a process exits.
/// Generated from `do_group_exit()`.
/// The `exit_code` contains the raw kernel exit status.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub exit_code: i32,
}

impl Display for ProcessExitEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} EXIT {}", self.header, self.status(),)
    }
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

impl Display for ProcessForkEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} FORK {}({})",
            self.parent, self.child_comm, self.child_pid,
        )
    }
}

/// A process lifecycle event.
///
/// This enum groups all process-related events emitted by bpfx, including
/// process creation, program execution, and process termination.
///
/// Use pattern matching or the provided helper methods to inspect the
/// underlying event.
///
/// This enum is marked as `non_exhaustive` and may gain additional variants
/// in future releases.
#[non_exhaustive]
#[derive(Debug)]
pub enum ProcessEvent {
    Start(ProcessStartEvent),
    Fork(ProcessForkEvent),
    Exit(ProcessExitEvent),
}

impl Display for ProcessEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Start(e) => e.fmt(f),
            Self::Fork(e) => e.fmt(f),
            Self::Exit(e) => e.fmt(f),
        }
    }
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

/// A stream of process events.
///
/// Instances of this type are returned by [`Bpfx::subscribe`] when subscribing
/// with a [`ProcessFilter`].
///
/// Implements [`futures::Stream`], yielding [`ProcessEvent`].
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

/// Bitmask describing which process events should generate notifications.
///
/// # Examples
///
/// ```rust
/// # use bpfx::network::ProcessMask;
/// let mask = ProcessMask::START | ProcessMask::EXIT;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Configures which process events are delivered.
///
/// A `ProcessFilter` controls:
///
/// - which process events generate notifications (`mask`)
/// - an optional process or user filter (`filter`)
///
/// # Examples
///
/// Monitor process creation events:
///
/// ```rust
/// # use bpfx::process::ProcessFilter;
/// let filter = ProcessFilter::START;
/// ```
///
/// Monitor process exits for a specific user:
///
/// ```rust
/// # use bpfx::{process::{ProcessFilter, ProcessMask}, FilterKey};
/// let filter = ProcessFilter {
///     mask: ProcessMask::EXIT,
///     filter: FilterKey::Uid(1000),
/// };
/// ```
#[derive(Debug)]
pub struct ProcessFilter {
    pub mask: ProcessMask,
    pub filter: FilterKey,
}

/// Internal registration state for a process event subscription.
///
/// Stores the active filter and the channel used to deliver events
/// to the corresponding event stream.
#[derive(Debug)]
pub(crate) struct ProcessRegister {
    pub filter: ProcessFilter,
    pub tx: Sender<ProcessEvent>,
}

impl Subscription for ProcessFilter {
    type Event = ProcessEvent;
    type Stream = PollProcess;

    fn subscribe(self, bpfx: &mut Bpfx) -> Result<Self::Stream> {
        let (tx, rx) = tokio::sync::mpsc::channel::<ProcessEvent>(bpfx.config.channel_capacity);
        let pr = ProcessRegister { filter: self, tx };
        attach_process_probe(&pr.filter, &mut bpfx.bpf, &bpfx.btf)?;
        bpfx.process = Some(pr);

        Ok(PollProcess { rx })
    }
}

impl Default for ProcessFilter {
    fn default() -> Self {
        Self {
            mask: ProcessMask::ALL,
            filter: FilterKey::None,
        }
    }
}

impl ProcessFilter {
    pub const START: Self = Self {
        mask: ProcessMask::START,
        filter: FilterKey::None,
    };

    pub const FORK: Self = Self {
        mask: ProcessMask::FORK,
        filter: FilterKey::None,
    };

    pub const EXIT: Self = Self {
        mask: ProcessMask::EXIT,
        filter: FilterKey::None,
    };

    pub const ALL: Self = Self {
        mask: ProcessMask::ALL,
        filter: FilterKey::None,
    };
}
