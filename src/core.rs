use crate::error::Result;
use crate::file::{
    FileChmodEvent, FileChownEvent, FileCloseEvent, FileCreateEvent, FileDeleteEvent, FileEvent,
    FileFilter, FileOpenEvent, FileReadEvent, FileRegister, FileRenameEvent, FileSyncEvent,
    FileTruncateEvent, FileType, FileWriteEvent, MkdirEvent, RmdirEvent,
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
use aya::programs::{Lsm, TracePoint};
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::RingBuf,
    programs::{FEntry, FExit, KProbe},
};
use aya_log::EbpfLogger;
use bpfx_common::raw::*;
use std::collections::HashMap;
use std::os::fd::AsRawFd;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::{self, error::TrySendError};

const MAX_PENDING_RENAMES: usize = 1024;

/// Configuration options for a [`Bpfx`] runtime.
///
/// Use [`Bpfx::with_config`] to create a runtime with custom settings.
/// # Example
/// ```no_run
/// let mut bpfx = Bpfx::with_config(BpfxConfig::default().channel_capacity(10_000))?;
/// ```
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

impl BpfxConfig {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
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
/// let events = bpfx.subscribe(ProcessFilter::ALL)?;
///
/// let _runtime = bpfx.run();
///
/// while let Some(events) = events.next().await {
///     // do something
/// }
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
        let mut bpf = Ebpf::load(include_bytes_aligned!("../assets/bpfx-ebpf.o"))?;

        if let Err(e) = EbpfLogger::init(&mut bpf) {
            log::debug!("failed to initialize eBPF logger: {e}");
        }

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
        let mut bpf = Ebpf::load(include_bytes_aligned!("../assets/bpfx-ebpf.o"))?;

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
    pub fn run(self) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move {
            log::info!("Bpfx runtime task started");

            let result = self.event_loop().await;

            match &result {
                Ok(()) => {
                    log::info!("Bpfx runtime stopped normally");
                }
                Err(e) => {
                    log::error!("Bpfx runtime failed: {e:?}");
                }
            }

            result
        })
    }

    async fn event_loop(mut self) -> Result<()> {
        log::info!("event loop started");
        let fd = self.ringbuf.as_raw_fd();
        let async_fd = AsyncFd::new(fd)?;

        loop {
            let mut ready = async_fd.readable().await?;

            if !self.has_subscribers() {
                log::info!("all subscriptions dropped, shutting down event loop");
                break;
            }

            while let Some(events) = self.ringbuf.next() {
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

            ready.clear_ready();
        }

        Ok(())
    }
}

fn parse_network_event(event: &PendingConnect) -> (EventHeader, SocketEndpoints) {
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
    (rest, $variant: ident, $ty: ident, $header: expr, $file_path: expr, $file_type: expr, $inode: expr, $retval: expr, $flags: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            file_path: $file_path,
            file_type: $file_type,
            inode: $inode,
            retval: $retval,
            flags: $flags,
        })
    };

    (no_flags, $variant: ident, $ty: ident, $header: expr, $file_path: expr, $inode: expr, $mode: expr, $retval: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            file_path: $file_path,
            inode: $inode,
            mode: $mode,
            retval: $retval,
        })
    };

    (truncate, $variant: ident, $ty: ident, $header: expr, $file_path: expr, $inode: expr, $requested_size: expr, $mode: expr, $retval: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            file_path: $file_path,
            inode: $inode,
            requested_size: $requested_size,
            mode: $mode,
            retval: $retval,
        })
    };

    (delete, $variant: ident, $ty: ident, $header: expr, $filename: expr, $file_type: expr, $retval: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            filename: $filename,
            file_type: $file_type,
            retval: $retval,
        })
    };

    (rename, $variant: ident, $ty: ident, $header: expr, $old_filename: expr, $new_filename: expr, $file_type: expr, $retval: expr, $flags: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            old_filename: $old_filename,
            new_filename: $new_filename,
            file_type: $file_type,
            retval: $retval,
            flags: $flags,
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

pub(crate) const TCP_CONNECT: &[(&str, &str)] = &[
    ("tcp_v4_connect", "tcp_v4_connect"),
    ("tcp_v6_connect", "tcp_v6_connect"),
];

pub(crate) const TCP_ACCEPT: &[(&str, &str)] = &[("inet_csk_accept", "inet_csk_accept")];

pub(crate) const TCP_CLOSE: (&str, &str) = ("tcp_close", "tcp_close");

pub(crate) const UDP_CONNECT: &[(&str, &str)] = &[
    ("udp_connect", "udp_connect"),
    ("udpv6_connect", "udpv6_connect"),
];

pub(crate) const UDP_CLOSE: (&str, &str) = ("udp_destroy_sock", "udp_destroy_sock");

pub(crate) fn attach_fexit(
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

pub(crate) fn attach_kprobe(
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

pub(crate) fn attach_fentry(
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

pub(crate) fn attach_tracepoint(
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

fn check_size<T>(len: usize) -> Result<()> {
    if len != std::mem::size_of::<T>() {
        return Err(crate::error::Error::MalformedEvent);
    }
    Ok(())
}

pub fn convert_network_events(
    producer: &mpsc::Sender<NetworkEvent>,
    events: &RingBufItem<'_>,
) -> crate::error::Result<()> {
    let ptr = events.as_ptr();

    check_size::<PendingConnect>(events.len())?;

    let event = unsafe { std::ptr::read_unaligned(ptr.cast::<PendingConnect>()) };

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

    if events.len() < std::mem::size_of::<RawEventHeader>() {
        return Err(crate::error::Error::MalformedEvent);
    }

    let header = unsafe { std::ptr::read_unaligned(ptr as *const RawEventHeader) };

    match header.event_type {
        EventType::ProcessStart => {
            check_size::<RawProcessStartEvent>(events.len())?;

            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawProcessStartEvent) };

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
            check_size::<RawProcessExitEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawProcessExitEvent) };

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
            check_size::<RawProcessForkEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawProcessForkEvent) };

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

    attach_lsm_probe(bpf, btf)?;

    attach_fexit(bpf, btf, "__fput", "__fput")?;

    if filter.event_type.contains(&FileMask::FILE_CHMOD) {
        attach_fexit(bpf, btf, "chmod_common_exit", "chmod_common")?;
        attach_lsm(bpf, btf, "path_chmod")?;
    }

    if filter.event_type.contains(&FileMask::FILE_CHOWN) {
        attach_fexit(bpf, btf, "chown_common_exit", "chown_common")?;
        attach_lsm(bpf, btf, "path_chown")?;
    }

    if filter.event_type.contains(&FileMask::FILE_SYNC) {
        attach_fexit(bpf, btf, "vfs_fsync_range_exit", "vfs_fsync_range")?;
    }

    if filter.event_type.contains(&FileMask::TRUNCATE) {
        attach_fexit(bpf, btf, "do_truncate_exit", "do_truncate")?;
        attach_fexit(bpf, btf, "vfs_truncate_exit", "vfs_truncate")?;
        attach_fentry(bpf, btf, "vfs_truncate_enter", "vfs_truncate")?;
    }

    if filter.event_type.contains(&FileMask::MKDIR) {
        attach_lsm(bpf, btf, "path_mkdir")?;
        attach_fexit(bpf, btf, "vfs_mkdir", "vfs_mkdir")?;
    }

    if filter.event_type.contains(&FileMask::RMDIR) {
        attach_lsm(bpf, btf, "path_rmdir")?;
        attach_fexit(bpf, btf, "vfs_rmdir", "vfs_rmdir")?;
        attach_fexit(bpf, btf, "security_path_rmdir_exit", "security_path_rmdir")?;
    }

    if filter.event_type.contains(&FileMask::CREATE) {
        attach_fexit(bpf, btf, "do_filp_open", "do_filp_open")?;
    }

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
        attach_lsm(bpf, btf, "path_unlink")?;
        attach_fexit(bpf, btf, "vfs_unlink", "vfs_unlink")?;
    }

    if filter.event_type.contains(&FileMask::RENAME) {
        attach_fentry(bpf, btf, "vfs_rename", "vfs_rename")?;
        attach_fexit(bpf, btf, "vfs_rename_retval", "vfs_rename")?;
    }

    log::info!("attached file probe");

    Ok(())
}

pub(crate) fn attach_lsm_probe(bpf: &mut Ebpf, btf: &Btf) -> Result<()> {
    let program: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;

    program.load("file_open", &btf)?;

    program.attach()?;

    Ok(())
}

fn attach_lsm(bpf: &mut Ebpf, btf: &Btf, name: &str) -> crate::error::Result<()> {
    let program: &mut Lsm = bpf
        .program_mut(name)
        .expect(&format!("LSM program not found: {name}"))
        .try_into()?;

    program.load(name, btf)?;
    program.attach()?;

    Ok(())
}

fn convert_file_events(
    producer: &mpsc::Sender<FileEvent>,
    events: &RingBufItem<'_>,
    pending_rename_map: &mut HashMap<(u32, u32), RawFileRenameEvent>,
) -> crate::error::Result<()> {
    let ptr = events.as_ptr();

    if events.len() < size_of::<RawEventHeader>() {
        return Err(crate::error::Error::MalformedEvent);
    }
    let header = unsafe { std::ptr::read_unaligned(ptr as *const RawEventHeader) };

    match header.event_type {
        EventType::FileChmod => {
            check_size::<RawFileChmodEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileChmodEvent) };

            let file_path = if event.file_path[0] == 0 {
                None
            } else {
                let path_len = event
                    .file_path
                    .iter()
                    .position(|&x| x == 0)
                    .unwrap_or(event.file_path.len());
                Some(String::from_utf8_lossy(&event.file_path[..path_len]).into_owned())
            };

            match producer.try_send(FileEvent::FileChmod(FileChmodEvent {
                header: convert_header(event.header),
                file_path,
                inode: event.inode,
                requested_mode: event.requested_mode,
                inode_mode: event.inode_mode,
                retval: event.retval as i32,
            })) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileChown => {
            check_size::<RawFileChownEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileChownEvent) };

            let file_path = if event.file_path[0] == 0 {
                None
            } else {
                let path_len = event
                    .file_path
                    .iter()
                    .position(|&x| x == 0)
                    .unwrap_or(event.file_path.len());
                Some(String::from_utf8_lossy(&event.file_path[..path_len]).into_owned())
            };

            match producer.try_send(FileEvent::FileChown(FileChownEvent {
                header: convert_header(event.header),
                file_path,
                inode: event.inode,
                requested_uid: (event.requested_uid != u32::MAX).then_some(event.requested_uid),
                requested_gid: (event.requested_gid != u32::MAX).then_some(event.requested_gid),
                retval: event.retval as i32,
            })) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::FileSync => {
            check_size::<RawFileSyncEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileSyncEvent) };

            let file_path = if event.file_path[0] == 0 {
                None
            } else {
                let path_len = event
                    .file_path
                    .iter()
                    .position(|&x| x == 0)
                    .unwrap_or(event.file_path.len());
                Some(String::from_utf8_lossy(&event.file_path[..path_len]).into_owned())
            };

            match producer.try_send(FileEvent::FileSync(FileSyncEvent {
                header: convert_header(event.header),
                file_path,
                inode: event.inode,
                start: event.start,
                end: event.end,
                datasync: event.datasync != 0,
                retval: event.retval as i32,
                mode: event.mode,
            })) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    log::warn!("dropping file event: channel is full");
                }
                Err(TrySendError::Closed(_)) => {
                    log::warn!("dropping file event: receiver has been closed");
                }
            }
        }

        EventType::Truncate => {
            check_size::<RawFileTruncateEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileTruncateEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                truncate,
                Truncate,
                FileTruncateEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                event.inode,
                event.requested_size,
                event.mode,
                event.retval as i32
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
        EventType::Mkdir => {
            check_size::<RawMkdirEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawMkdirEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                no_flags,
                Mkdir,
                MkdirEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                event.inode,
                event.mode,
                event.retval as i32
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
        EventType::Rmdir => {
            check_size::<RawRmdirEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawRmdirEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                no_flags,
                Rmdir,
                RmdirEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                event.inode,
                event.mode,
                event.retval as i32
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
        EventType::FileCreate => {
            check_size::<RawFileCreateEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileCreateEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                rest,
                Create,
                FileCreateEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.inode,
                event.retval,
                event.flags
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
        EventType::FileOpen => {
            check_size::<RawFileOpenEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileOpenEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                rest,
                Open,
                FileOpenEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.inode,
                event.retval,
                event.flags
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
            check_size::<RawFileCloseEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileCloseEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                rest,
                Close,
                FileCloseEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.inode,
                event.retval,
                event.flags
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
            check_size::<RawFileReadEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileReadEvent) };
            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                rest,
                Read,
                FileReadEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.inode,
                event.retval,
                event.flags
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
            check_size::<RawFileWriteEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileWriteEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                rest,
                Write,
                FileWriteEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
                FileType::from(event.file_mode),
                event.inode,
                event.retval,
                event.flags
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
            check_size::<RawFileDeleteEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileDeleteEvent) };

            let path_len = event
                .file_path
                .iter()
                .position(|&x| x == 0)
                .unwrap_or(event.file_path.len());

            match producer.try_send(file_event!(
                delete,
                Delete,
                FileDeleteEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.file_path[..path_len]).into_owned(),
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
            check_size::<RawFileRenameEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileRenameEvent) };

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
            check_size::<RawFileRtrEvent>(events.len())?;
            let ret_event = unsafe { std::ptr::read_unaligned(ptr as *const RawFileRtrEvent) };
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
                    rename,
                    Rename,
                    FileRenameEvent,
                    convert_header(event.header),
                    String::from_utf8_lossy(&event.old_filename[..old_path_len]).into_owned(),
                    String::from_utf8_lossy(&event.new_filename[..new_path_len]).into_owned(),
                    FileType::from(event.file_mode),
                    ret_event.retval,
                    event.flags
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
    if events.len() < size_of::<RawEventHeader>() {
        return Err(crate::error::Error::MalformedEvent);
    }

    let header = unsafe { ptr::read(ptr as *const RawEventHeader) };

    match header.event_type {
        EventType::MemoryMap => {
            check_size::<RawMemoryMapEvent>(events.len())?;
            let event = unsafe { std::ptr::read_unaligned(ptr as *const RawMemoryMapEvent) };

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
            check_size::<RawMemoryUnmapEvent>(events.len())?;
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
