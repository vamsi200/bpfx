use crate::error::Result;
use crate::file::{
    FileCloseEvent, FileDeleteEvent, FileEvent, FileFilter, FileOpenEvent, FileReadEvent,
    FileRegister, FileRenameEvent, FileType, FileWriteEvent,
};
use crate::memory::MemRegister;
use crate::memory::MemoryUnmapEvent;
use crate::memory::{MemoryEvent, MemoryFilter, MemoryMapEvent, MemoryMask};
use crate::network::{
    BindEvent, ListenEvent, NetworkFilter, NetworkRegister, Protocol, ProtocolMask,
};
use crate::process::{ProcessEvent, ProcessExitEvent, ProcessFilter, ProcessMask};
use crate::{FileMask, NetworkMask, process::*};
use crate::{
    common::EventHeader,
    network::{AcceptEvent, CloseEvent, ConnectEvent, NetworkEvent, SocketEndpoints},
};
use aya::maps::MapData;
use aya::maps::ring_buf::RingBufItem;
use aya::programs::TracePoint;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::RingBuf,
    programs::{FEntry, FExit, KProbe},
};
use bpfx_common::raw::*;
use std::collections::HashMap;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use tokio::sync::mpsc::{self, error::TrySendError};
const MAX_PENDING_RENAMES: usize = 1024;

/// Configuration options for a [`Bpfx`] runtime.
///
/// Use [`Bpfx::with_config`] to create a runtime with custom settings.
#[non_exhaustive]
pub struct BpfxConfig {
    /// Capacity of the per-subscription event channel.
    ///
    /// The default value used by [`Bpfx::new`] is `1024`.
    pub channel_capacity: usize,
}

impl Default for BpfxConfig {
    fn default() -> Self {
        Self {
            channel_capacity: 1024,
        }
    }
}

/// Entry point for bpfx.
///
/// `Bpfx` owns the loaded eBPF programs, kernel metadata, and the internal
/// event loop used to deliver events to subscribers.
///
/// A typical workflow is:
///
/// 1. Construct a [`Bpfx`] instance with [`Bpfx::new`].
/// 2. Register one or more subscriptions using [`Bpfx::subscribe`].
/// 3. Start the event loop with [`Bpfx::run`].
///
/// # Example
///
/// ```no_run
/// use bpfx::{
///     process::ProcessFilter,
///     Bpfx,
/// };
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut bpfx = Bpfx::new()?;
///
/// let _events = bpfx.subscribe(ProcessFilter::ALL)?;
///
/// let runtime = bpfx.run();
///
/// runtime.await??;
/// # Ok(())
/// # }
/// ```
pub struct Bpfx {
    pub(crate) bpf: Ebpf,
    pub(crate) btf: Btf,
    ringbuf: RingBuf<MapData>,
    pub(crate) network: Option<NetworkRegister>,
    pub(crate) process: Option<ProcessRegister>,
    pub(crate) file: Option<FileRegister>,
    pub(crate) mem: Option<MemRegister>,
    started: bool,
    pending_renames: HashMap<(u32, u32), RawFileRenameEvent>,
    pub config: BpfxConfig,
}

/// A type that can register an event subscription with [`Bpfx`].
///
/// This trait is implemented by all filter types (for example,
/// `ProcessFilter`, `FileFilter`, `MemoryFilter`, and `NetworkFilter`).
///
/// Users typically do not implement this trait directly. Instead, it is used
/// by [`Bpfx::subscribe`] to create the corresponding event stream.
pub trait Subscription {
    type Event;
    type Stream;

    fn subscribe(self, bpfx: &mut Bpfx) -> crate::error::Result<Self::Stream>;
}

impl Bpfx {
    /// Creates a new bpfx runtime.
    ///
    /// This loads the embedded eBPF object, initializes kernel BTF information,
    /// and prepares the internal ring buffer used to receive events.
    ///
    /// The returned instance is inert until one or more subscriptions are
    /// registered and [`Bpfx::run`] is called.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - the embedded eBPF object cannot be loaded,
    /// - kernel BTF information is unavailable,
    /// - the event ring buffer cannot be initialized.
    pub fn new() -> Result<Self> {
        log::info!("loading eBPF object");
        let mut bpf = Ebpf::load(include_bytes_aligned!(env!("BPFX_EBPF")))?;

        log::debug!("loading kernel BTF");
        let btf = Btf::from_sys_fs()?;

        log::debug!("retrieving EVENTS ring buffer map");
        let events = bpf
            .take_map("EVENTS")
            .ok_or_else(|| crate::error::Error::EventsMapAccess)?;

        log::debug!("creating ring buffer");
        let ringbuf = RingBuf::try_from(events)?;

        log::info!("bpfx initialized successfully");

        Ok(Self {
            bpf,
            btf,
            ringbuf,
            network: None,
            process: None,
            file: None,
            mem: None,
            started: false,
            pending_renames: HashMap::with_capacity(1000),
            config: BpfxConfig {
                channel_capacity: 1024,
            },
        })
    }

    /// Creates a new bpfx runtime using the provided configuration.
    ///
    /// This loads the embedded eBPF object, initializes kernel BTF information,
    /// and prepares the internal ring buffer used to receive events.
    ///
    /// The provided [`BpfxConfig`] controls runtime behavior such as the event
    /// channel capacity used for subscriptions.
    ///
    /// The returned instance is inert until one or more subscriptions are
    /// registered and [`Bpfx::run`] is called.
    ///
    /// # Parameters
    ///
    /// - `config` - Runtime configuration for the bpfx instance.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - the embedded eBPF object cannot be loaded,
    /// - kernel BTF information is unavailable,
    /// - the event ring buffer cannot be initialized.
    pub fn with_config(config: BpfxConfig) -> Result<Self> {
        log::info!("loading eBPF object");
        let mut bpf = Ebpf::load(include_bytes_aligned!(env!("BPFX_EBPF")))?;

        log::debug!("loading kernel BTF");
        let btf = Btf::from_sys_fs()?;

        log::debug!("retrieving EVENTS ring buffer map");
        let events = bpf
            .take_map("EVENTS")
            .ok_or_else(|| crate::error::Error::EventsMapAccess)?;

        log::debug!("creating ring buffer");
        let ringbuf = RingBuf::try_from(events)?;

        log::info!(
            "bpfx initialized successfully (channel_capacity={})",
            config.channel_capacity
        );

        Ok(Self {
            bpf,
            btf,
            ringbuf,
            network: None,
            process: None,
            file: None,
            mem: None,
            started: false,
            pending_renames: HashMap::with_capacity(1000),
            config,
        })
    }

    fn has_subscribers(&self) -> bool {
        self.network.as_ref().is_some_and(|r| !r.tx.is_closed())
            || self.process.as_ref().is_some_and(|r| !r.tx.is_closed())
            || self.file.as_ref().is_some_and(|r| !r.tx.is_closed())
            || self.mem.as_ref().is_some_and(|r| !r.tx.is_closed())
    }

    /// Registers a new event subscription.
    ///
    /// The supplied filter determines which events are monitored and returned
    /// by the resulting event stream.
    ///
    /// Multiple subscriptions of different types may coexist.
    ///
    /// # Errors
    ///
    /// Returns an error if the required eBPF probes cannot be attached.
    pub fn subscribe<S>(&mut self, filter: S) -> Result<S::Stream>
    where
        S: Subscription,
    {
        log::info!("registering subscription");
        filter.subscribe(self)
    }

    /// Starts the bpfx event loop.
    ///
    /// This consumes the [`Bpfx`] instance and spawns a background Tokio task
    /// that continuously receives kernel events and dispatches them to active
    /// subscribers.
    ///
    /// The returned [`tokio::task::JoinHandle`] should typically be awaited to
    /// observe any runtime errors.
    ///
    /// The event loop exits automatically when all subscriptions have been
    /// dropped.
    ///
    /// # Panics
    ///
    /// Panics if called outside of a Tokio runtime.
    #[must_use = "call .await on the returned JoinHandle or explicitly drop it"]
    pub fn run(mut self) -> tokio::task::JoinHandle<Result<()>> {
        self.started = true;
        tokio::spawn(async move { self.event_loop().await })
    }

    async fn event_loop(mut self) -> Result<()> {
        log::info!("event loop started");
        loop {
            if !self.has_subscribers() {
                log::info!("all subscriptions dropped, shutting down event loop");
                break Err(crate::error::Error::NoActiveSubscriptions);
            }

            if let Some(events) = self.ringbuf.next() {
                if let Some(nr) = &self.network {
                    convert_network_events(&nr.tx, &events)?;
                }

                if let Some(pr) = &self.process {
                    convert_process_events(&pr.tx, &events)?;
                }

                if let Some(pr) = &self.file {
                    convert_file_events(&pr.tx, &events, &mut self.pending_renames)?;
                }

                if let Some(pr) = &self.mem {
                    convert_mem_events(&pr.tx, &events)?;
                }
            }
        }
    }
}

impl Drop for Bpfx {
    fn drop(&mut self) {
        if !self.started {
            log::warn!("Bpfx dropped without calling run()");
        }
    }
}

fn parse_network_event(event: &PendingConnect) -> (EventHeader, SocketEndpoints) {
    log::debug!("parsing network events");

    let len = event
        .header
        .comm
        .iter()
        .position(|&s| s == 0)
        .unwrap_or(event.header.comm.len());

    let header = EventHeader {
        timestamp_ns: event.header.timestamp_ns,
        pid: event.header.pid,
        tid: event.header.tid,
        ppid: event.header.ppid,
        uid: event.header.uid,
        gid: event.header.gid,
        comm: String::from_utf8_lossy(&event.header.comm[..len]).into_owned(),
    };

    let local_ip = match event.ip_version {
        IpVersion::V4 => IpAddr::V4(Ipv4Addr::from([
            event.src_addr[0],
            event.src_addr[1],
            event.src_addr[2],
            event.src_addr[3],
        ])),
        IpVersion::V6 => IpAddr::V6(Ipv6Addr::from(event.src_addr)),
    };

    let remote_ip = match event.ip_version {
        IpVersion::V4 => IpAddr::V4(Ipv4Addr::from([
            event.dst_addr[0],
            event.dst_addr[1],
            event.dst_addr[2],
            event.dst_addr[3],
        ])),
        IpVersion::V6 => IpAddr::V6(Ipv6Addr::from(event.dst_addr)),
    };

    let endpoints = SocketEndpoints {
        local_ip,
        remote_ip,
        local_port: event.src_port,
        remote_port: event.dst_port,
    };

    (header, endpoints)
}

macro_rules! network_event {
    ($variant:ident, $ty:ident, $header:expr, $protocol:expr, $endpoints:expr, $retval: expr) => {
        NetworkEvent::$variant($ty {
            header: $header,
            protocol: $protocol,
            endpoints: $endpoints,
            retval: $retval,
        })
    };

    ($variant:ident, $ty:ident, $header:expr, $protocol:expr, $endpoints:expr) => {
        NetworkEvent::$variant($ty {
            header: $header,
            protocol: $protocol,
            endpoints: $endpoints,
        })
    };
}

macro_rules! process_event {
    (start, $header:expr, $filename:expr) => {
        ProcessEvent::Start(ProcessStartEvent {
            header: $header,
            filename: $filename,
        })
    };

    (fork, $parent: expr, $child_pid: expr, $child_comm: expr) => {
        ProcessEvent::Fork(ProcessForkEvent {
            parent: $parent,
            child_pid: $child_pid,
            child_comm: $child_comm,
        })
    };

    (exit, $header:expr, $exit_code:expr) => {
        ProcessEvent::Exit(ProcessExitEvent {
            header: $header,
            exit_code: $exit_code,
        })
    };
}

macro_rules! file_event {
    ($variant: ident, $ty: ident, $header: expr, $filename: expr, $file_type: expr, $retval: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            filename: $filename,
            file_type: $file_type,
            retval: $retval,
        })
    };

    ($variant: ident, $ty: ident, $header: expr, $old_filename: expr, $new_filename: expr, $file_type: expr, $retval: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            old_filename: $old_filename,
            new_filename: $new_filename,
            file_type: $file_type,
            retval: $retval,
        })
    };
}

macro_rules! mem_event {
    ($variant: ident, $ty: ident, $header: expr, $requested_address: expr, $lenght: expr, $protection: expr,
     $flags: expr, $mapped_address: expr) => {
        MemoryEvent::$variant($ty {
            header: $header,
            requested_address: $requested_address,
            length: $lenght,
            protection: $protection,
            flags: $flags,
            mapped_address: $mapped_address,
        })
    };

    ($variant: ident, $ty: ident, $header: expr, $requested_address: expr, $length: expr, $mapped_address: expr) => {
        MemoryEvent::$variant($ty {
            header: $header,
            requested_address: $requested_address,
            length: $length,
            mapped_address: $mapped_address,
        })
    };
}

const TCP_CONNECT: &[(&str, &str)] = &[
    ("tcp_v4_connect", "tcp_v4_connect"),
    ("tcp_v6_connect", "tcp_v6_connect"),
];

const TCP_ACCEPT: &[(&str, &str)] = &[("inet_csk_accept", "inet_csk_accept")];

const TCP_CLOSE: (&str, &str) = ("tcp_close", "tcp_close");

const UDP_CONNECT: &[(&str, &str)] = &[
    ("udp_connect", "udp_connect"),
    ("udpv6_connect", "udpv6_connect"),
];

const UDP_CLOSE: (&str, &str) = ("udp_destroy_sock", "udp_destroy_sock");

fn attach_fexit(
    bpf: &mut Ebpf,
    btf: &Btf,
    prog_name: &'static str,
    func_name: &'static str,
) -> crate::error::Result<()> {
    log::info!("attaching fexit probe '{}' to '{}'", prog_name, func_name);
    let prog: &mut FExit = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramAccess)?
        .try_into()?;

    prog.load(func_name, btf)?;
    prog.attach()?;
    Ok(())
}

fn attach_kprobe(
    bpf: &mut Ebpf,
    prog_name: &'static str,
    symbol: &'static str,
) -> crate::error::Result<()> {
    log::info!("attaching kprobe probe '{}' to '{}'", prog_name, symbol);

    let prog: &mut KProbe = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramAccess)?
        .try_into()?;

    prog.load()?;
    prog.attach(symbol, 0)?;
    Ok(())
}

fn attach_fentry(
    bpf: &mut Ebpf,
    btf: &Btf,
    prog_name: &'static str,
    symbol: &'static str,
) -> crate::error::Result<()> {
    log::info!("attaching fentry probe '{}' to '{}'", prog_name, symbol);

    let prog: &mut FEntry = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramAccess)?
        .try_into()?;

    prog.load(symbol, btf)?;
    prog.attach()?;
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &'static str,
    category: &'static str,
    tracepoint: &'static str,
) -> crate::error::Result<()> {
    log::info!(
        "attaching tracepoint probe '{}' to '{}'",
        prog_name,
        tracepoint
    );

    let prog: &mut TracePoint = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramAccess)?
        .try_into()?;

    prog.load()?;
    prog.attach(category, tracepoint)?;
    Ok(())
}

fn handle_connect(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) {
    let (header, endpoints) = parse_network_event(event);

    match event.protocol {
        RawProtocol::Tcp => {
            match producer.try_send(network_event!(
                Connect,
                ConnectEvent,
                header,
                Protocol::Tcp,
                endpoints,
                event.retval.unwrap() // unwrap is fine here.
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping network event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping network event: receiver has been closed");
                }
            }
        }

        RawProtocol::Udp => {
            match producer.try_send(network_event!(
                Connect,
                ConnectEvent,
                header,
                Protocol::Udp,
                endpoints,
                event.retval.unwrap()
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping network event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping network event: receiver has been closed");
                }
            }
        }
    }
}

fn handle_tcp_accept(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) {
    let (header, endpoints) = parse_network_event(event);
    let protocol = crate::network::Protocol::Tcp;
    match producer.try_send(network_event!(
        Accept,
        AcceptEvent,
        header,
        protocol,
        endpoints
    )) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            log::warn!("dropping network event: channel is full");
        }
        Err(TrySendError::Closed(_)) => {
            log::warn!("dropping network event: receiver has been closed");
        }
    }
}

fn handle_close(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) {
    let (header, endpoints) = parse_network_event(event);

    match event.protocol {
        RawProtocol::Tcp => {
            match producer.try_send(network_event!(
                Close,
                CloseEvent,
                header,
                Protocol::Tcp,
                endpoints
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping network event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping network event: receiver has been closed");
                }
            }
        }

        RawProtocol::Udp => {
            match producer.try_send(network_event!(
                Close,
                CloseEvent,
                header,
                Protocol::Udp,
                endpoints
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping network event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping network event: receiver has been closed");
                }
            }
        }
    }
}

pub(crate) fn attach_network_probe(
    filter: &NetworkFilter,
    bpf: &mut Ebpf,
    btf: &Btf,
) -> crate::error::Result<()> {
    log::info!("attaching network probe..");
    write_to_fiter_map(&Filters::Network(filter), FilterOwner::Network, bpf)?;

    if filter.protocol_mask.contains(&ProtocolMask::TCP)
        && filter.event_mask.contains(&NetworkMask::CONNECT)
    {
        for probe in TCP_CONNECT {
            attach_fexit(bpf, btf, probe.0, probe.1)?;
        }
    }

    if filter.protocol_mask.contains(&ProtocolMask::TCP)
        && filter.event_mask.contains(&NetworkMask::ACCEPT)
    {
        for probe in TCP_ACCEPT {
            attach_kprobe(bpf, probe.0, probe.1)?;
        }
    }

    if filter.protocol_mask.contains(&ProtocolMask::TCP)
        && filter.event_mask.contains(&NetworkMask::CLOSE)
    {
        attach_fexit(bpf, btf, TCP_CLOSE.0, TCP_CLOSE.1)?;
    }

    if filter.protocol_mask.contains(&ProtocolMask::TCP)
        && filter.event_mask.contains(&NetworkMask::BIND)
    {
        attach_fexit(bpf, btf, "inet_bind", "inet_bind")?;
    }

    if filter.protocol_mask.contains(&ProtocolMask::TCP)
        && filter.event_mask.contains(&NetworkMask::LISTEN)
    {
        attach_fexit(bpf, btf, "inet_listen", "inet_listen")?;
    }

    if filter.protocol_mask.contains(&ProtocolMask::UDP)
        && filter.event_mask.contains(&NetworkMask::CONNECT)
    {
        for probe in UDP_CONNECT {
            attach_fexit(bpf, btf, probe.0, probe.1)?;
        }
    }

    if filter.protocol_mask.contains(&ProtocolMask::UDP)
        && filter.event_mask.contains(&NetworkMask::CLOSE)
    {
        attach_fexit(bpf, btf, UDP_CLOSE.0, UDP_CLOSE.1)?;
    }

    log::info!("attached network probe");
    Ok(())
}

fn handle_bind(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) {
    let (header, endpoints) = parse_network_event(event);
    let protocol = crate::network::Protocol::Tcp;
    match producer.try_send(network_event!(
        Bind,
        BindEvent,
        header,
        protocol,
        endpoints,
        event.retval.unwrap() // unwrap here is fine.
    )) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            log::warn!("dropping network event: channel is full");
        }
        Err(TrySendError::Closed(_)) => {
            log::warn!("dropping network event: receiver has been closed");
        }
    }
}

fn handle_listen(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) {
    let (header, endpoints) = parse_network_event(event);
    let protocol = crate::network::Protocol::Tcp;

    match producer.try_send(network_event!(
        Listen,
        ListenEvent,
        header,
        protocol,
        endpoints,
        event.retval.unwrap()
    )) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            log::warn!("dropping network event: channel is full");
        }
        Err(TrySendError::Closed(_)) => {
            log::warn!("dropping network event: receiver has been closed");
        }
    }
}

pub fn convert_network_events(
    producer: &mpsc::Sender<NetworkEvent>,
    events: &RingBufItem<'_>,
) -> crate::error::Result<()> {
    let ptr = events.as_ptr();
    let event = unsafe { ptr::read(ptr as *const PendingConnect) };

    match event.header.event_type {
        EventType::Connect => handle_connect(&event, producer),
        EventType::Accept => handle_tcp_accept(&event, producer),
        EventType::Close => handle_close(&event, producer),
        EventType::Bind => handle_bind(&event, producer),
        EventType::Listen => handle_listen(&event, producer),
        _ => {}
    }

    Ok(())
}

pub(crate) fn attach_process_probe(
    filter: &ProcessFilter,
    bpf: &mut Ebpf,
    btf: &Btf,
) -> crate::error::Result<()> {
    write_to_fiter_map(&Filters::Process(filter), FilterOwner::Process, bpf)?;

    if filter.mask.contains(&ProcessMask::START) {
        attach_tracepoint(bpf, "sched_process_exec", "sched", "sched_process_exec")?;
    }

    if filter.mask.contains(&ProcessMask::FORK) {
        attach_tracepoint(bpf, "sched_process_fork", "sched", "sched_process_fork")?;
    }

    if filter.mask.contains(&ProcessMask::EXIT) {
        attach_fentry(bpf, btf, "do_group_exit", "do_group_exit")?;
    }

    log::info!("attached process probe");

    Ok(())
}

fn convert_header(header: RawEventHeader) -> EventHeader {
    let len = header
        .comm
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(header.comm.len());

    EventHeader {
        timestamp_ns: header.timestamp_ns,
        pid: header.pid,
        tid: header.tid,
        ppid: header.ppid,
        uid: header.uid,
        gid: header.gid,
        comm: String::from_utf8_lossy(&header.comm[..len]).into_owned(),
    }
}

fn convert_process_events(
    producer: &mpsc::Sender<ProcessEvent>,
    events: &RingBufItem<'_>,
) -> crate::error::Result<()> {
    let ptr = events.as_ptr();
    let header = unsafe { ptr::read(ptr as *const RawEventHeader) };

    match header.event_type {
        EventType::ProcessStart => {
            let event = unsafe { ptr::read(ptr as *const RawProcessStartEvent) };

            let file_name_len = event
                .filename
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.filename.len());

            match producer.try_send(process_event!(
                start,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..file_name_len]).into_owned()
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping process event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping process event: receiver has been closed");
                }
            }
        }

        EventType::ProcessExit => {
            let event = unsafe { ptr::read(ptr as *const RawProcessExitEvent) };

            match producer.try_send(process_event!(
                exit,
                convert_header(event.header),
                event.exit_code
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping process event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping process event: receiver has been closed");
                }
            };
        }

        EventType::ProcessFork => {
            let event = unsafe { ptr::read(ptr as *const RawProcessForkEvent) };

            let comm_len = event
                .child_comm
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.child_comm.len());

            match producer.try_send(process_event!(
                fork,
                convert_header(event.parent),
                event.child_pid,
                String::from_utf8_lossy(&event.child_comm[..comm_len]).into_owned()
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping process event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping process event: receiver has been closed");
                }
            };
        }
        _ => {}
    }

    Ok(())
}

fn write_to_map(bpf: &mut Ebpf, filter: &FileFilter) -> crate::error::Result<()> {
    use aya::maps::HashMap;

    let mut config: HashMap<_, u32, FileModeFilter> = HashMap::try_from(
        bpf.map_mut("CONFIG")
            .ok_or(crate::error::Error::ConfigMapAccess)?,
    )?;

    config.insert(0, FileModeFilter::from(filter.file_mode.clone()), 0)?;

    Ok(())
}

pub(crate) fn attach_file_probe(
    filter: &FileFilter,
    bpf: &mut Ebpf,
    btf: &Btf,
) -> crate::error::Result<()> {
    write_to_fiter_map(&Filters::File(filter), FilterOwner::File, bpf)?;
    write_to_map(bpf, filter)?;

    if filter.event_type.contains(&FileMask::OPEN) {
        attach_fexit(bpf, btf, "vfs_open", "vfs_open")?;
    }

    if filter.event_type.contains(&FileMask::CLOSE) {
        attach_fexit(bpf, btf, "filp_close", "filp_close")?;
    }

    if filter.event_type.contains(&FileMask::READ) {
        attach_fexit(bpf, btf, "vfs_read", "vfs_read")?;
    }

    if filter.event_type.contains(&FileMask::WRITE) {
        attach_fexit(bpf, btf, "vfs_write", "vfs_write")?;
    }

    if filter.event_type.contains(&FileMask::DELETE) {
        attach_fexit(bpf, btf, "vfs_unlink", "vfs_unlink")?;
    }

    if filter.event_type.contains(&FileMask::RENAME) {
        attach_fentry(bpf, btf, "vfs_rename", "vfs_rename")?;
        attach_fexit(bpf, btf, "vfs_rename_retval", "vfs_rename")?;
    }

    log::info!("attached file probe");

    Ok(())
}

fn convert_file_events(
    producer: &mpsc::Sender<FileEvent>,
    events: &RingBufItem<'_>,
    pending_rename_map: &mut HashMap<(u32, u32), RawFileRenameEvent>,
) -> crate::error::Result<()> {
    let ptr = events.as_ptr();
    let header = unsafe { ptr::read(ptr as *const RawEventHeader) };

    match header.event_type {
        EventType::FileOpen => {
            let event = unsafe { ptr::read(ptr as *const RawFileOpenEvent) };

            let path_len = event
                .filename
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.filename.len());

            match producer.try_send(file_event!(
                Open,
                FileOpenEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.retval
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileClose => {
            let event = unsafe { ptr::read(ptr as *const RawFileCloseEvent) };
            let path_len = event
                .filename
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.filename.len());

            match producer.try_send(file_event!(
                Close,
                FileCloseEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.retval
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileRead => {
            let event = unsafe { ptr::read(ptr as *const RawFileReadEvent) };
            let path_len = event
                .filename
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.filename.len());

            match producer.try_send(file_event!(
                Read,
                FileReadEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.retval
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileWrite => {
            let event = unsafe { ptr::read(ptr as *const RawFileWriteEvent) };
            let path_len = event
                .filename
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.filename.len());

            match producer.try_send(file_event!(
                Write,
                FileWriteEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.retval
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileDelete => {
            let event = unsafe { ptr::read(ptr as *const RawFileDeleteEvent) };
            let path_len = event
                .filename
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.filename.len());

            match producer.try_send(file_event!(
                Delete,
                FileDeleteEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.retval
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileRename => {
            let event = unsafe { ptr::read(ptr as *const RawFileRenameEvent) };
            let pid_tid = (event.header.pid, event.header.tid);

            if pending_rename_map.len() >= MAX_PENDING_RENAMES {
                log::warn!(
                    "pending rename map full ({} entries), dropping events",
                    MAX_PENDING_RENAMES
                );
            } else {
                match pending_rename_map.insert(pid_tid, event) {
                    Some(old) => {
                        log::warn!("replaced existing pending rename: {:?}", old);
                    }
                    None => {
                        log::info!("inserted new pending rename");
                    }
                }
            }
        }

        EventType::PendingFileRename => {
            let ret_event = unsafe { ptr::read(ptr as *const RawFileRtrEvent) };

            let pid_tid = (ret_event.header.pid, ret_event.header.tid);

            if let Some(event) = pending_rename_map.remove(&pid_tid) {
                let old_path_len = event
                    .old_filename
                    .iter()
                    .position(|&x| x == 0)
                    .unwrap_or(event.old_filename.len());

                let new_path_len = event
                    .new_filename
                    .iter()
                    .position(|&x| x == 0)
                    .unwrap_or(event.new_filename.len());

                match producer.try_send(file_event!(
                    Rename,
                    FileRenameEvent,
                    convert_header(event.header),
                    String::from_utf8_lossy(&event.old_filename[..old_path_len]).into_owned(),
                    String::from_utf8_lossy(&event.new_filename[..new_path_len]).into_owned(),
                    FileType::from(event.file_mode),
                    ret_event.retval
                )) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        log::warn!("dropping file event: channel is full");
                    }
                    Err(TrySendError::Closed(_)) => {
                        log::warn!("dropping file event: receiver has been closed");
                    }
                }
            } else {
                log::debug!("orphaned rename exit for {:?}", pid_tid);
            }
        }

        _ => {}
    }

    Ok(())
}

enum Filters<'a> {
    Memory(&'a MemoryFilter),
    File(&'a FileFilter),
    Network(&'a NetworkFilter),
    Process(&'a ProcessFilter),
}

fn write_to_fiter_map(
    filter_type: &Filters,
    owner: FilterOwner,
    bpf: &mut Ebpf,
) -> crate::error::Result<()> {
    use aya::maps::HashMap;

    let mut filter: HashMap<_, u32, FilterKey> = HashMap::try_from(
        bpf.map_mut("FILTER")
            .ok_or(crate::error::Error::FilterMapAccess)?,
    )?;

    let filter_type = match filter_type {
        Filters::Memory(m) => m.filter,
        Filters::File(f) => f.filter,
        Filters::Network(n) => n.filter,
        Filters::Process(p) => p.filter,
    };

    filter.insert(owner as u32, filter_type, 0)?;
    Ok(())
}

pub(crate) fn attach_mem_probe(
    filter: &MemoryFilter,
    bpf: &mut Ebpf,
    btf: &Btf,
) -> crate::error::Result<()> {
    write_to_fiter_map(&Filters::Memory(filter), FilterOwner::Memory, bpf)?;

    if filter.mask.contains(MemoryMask::MMAP) {
        attach_fexit(bpf, btf, "vm_mmap_pgoff", "vm_mmap_pgoff")?;
    }

    if filter.mask.contains(MemoryMask::UNMAP) {
        attach_fexit(bpf, btf, "__vm_munmap", "__vm_munmap")?;
    }

    log::info!("attached memory probe");

    Ok(())
}

fn convert_mem_events(
    producer: &mpsc::Sender<MemoryEvent>,
    events: &RingBufItem<'_>,
) -> crate::error::Result<()> {
    let ptr = events.as_ptr();
    let header = unsafe { ptr::read(ptr as *const RawEventHeader) };

    match header.event_type {
        EventType::MemoryMap => {
            let event = unsafe { ptr::read(ptr as *const RawMemoryMapEvent) };
            match producer.try_send(mem_event!(
                MemoryMap,
                MemoryMapEvent,
                convert_header(event.header),
                event.requested_address,
                event.length,
                event.protection,
                event.flags,
                event.mapped_address
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping memory event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping memory event: receiver has been closed");
                }
            }
        }

        EventType::MemoryUnMap => {
            let event = unsafe { ptr::read(ptr as *const RawMemoryUnmapEvent) };
            match producer.try_send(mem_event!(
                MemoryUnMap,
                MemoryUnmapEvent,
                convert_header(event.header),
                event.requested_address,
                event.length,
                event.mapped_address
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping memory event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping memory event: receiver has been closed");
                }
            }
        }
        _ => {}
    }

    Ok(())
}
