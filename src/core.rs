use crate::error::Result;
use crate::file::{
    FileCloseEvent, FileDeleteEvent, FileEvent, FileFilter, FileOpenEvent, FileReadEvent,
    FileRegister, FileRenameEvent, FileType, FileWriteEvent,
};
use crate::memory::{MemRegister, MemoryUnmapEvent};
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
use aya_log::EbpfLogger;
use bpfx_common::raw::*;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use tokio::sync::mpsc::{self, error::TrySendError};

pub struct Bpfx {
    pub bpf: Ebpf,
    pub btf: Btf,
    ringbuf: RingBuf<MapData>,
    pub network: Option<NetworkRegister>,
    pub process: Option<ProcessRegister>,
    pub file: Option<FileRegister>,
    pub mem: Option<MemRegister>,
}

pub trait Subscription {
    type Event;
    type Stream;

    fn subscribe(self, bpfx: &mut Bpfx) -> crate::error::Result<Self::Stream>;
}

impl Bpfx {
    pub fn new() -> Result<Self> {
        env_logger::init();

        let mut bpf = Ebpf::load(include_bytes_aligned!(env!("BPFX_EBPF")))?;

        let btf = Btf::from_sys_fs()?;

        if let Err(e) = EbpfLogger::init(&mut bpf) {
            log::debug!("failed to initialize eBPF logger: {e}");
        }

        let events = bpf
            .take_map("EVENTS")
            .ok_or_else(|| crate::error::Error::EventNotFound)?;

        let ringbuf = RingBuf::try_from(events)?;
        Ok(Self {
            bpf,
            btf,
            ringbuf,
            network: None,
            process: None,
            file: None,
            mem: None,
        })
    }

    pub fn subscribe<S>(&mut self, filter: S) -> Result<S::Stream>
    where
        S: Subscription,
    {
        filter.subscribe(self)
    }

    pub fn run(self) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async move { self.run_boy().await })
    }

    async fn run_boy(mut self) -> Result<()> {
        loop {
            if let Some(events) = self.ringbuf.next() {
                if let Some(nr) = &self.network {
                    convert_network_events(&nr.tx, &events)?;
                }

                if let Some(pr) = &self.process {
                    convert_process_events(&pr.tx, &events)?;
                }

                if let Some(pr) = &self.file {
                    convert_file_events(&pr.tx, &events)?;
                }

                if let Some(pr) = &self.mem {
                    convert_mem_events(&pr.tx, &events)?;
                }
            }
        }
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
    let prog: &mut FExit = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramNotFound)?
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
    let prog: &mut KProbe = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramNotFound)?
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
    let prog: &mut FEntry = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramNotFound)?
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
    let prog: &mut TracePoint = bpf
        .program_mut(prog_name)
        .ok_or(crate::error::Error::ProgramNotFound)?
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

pub fn attach_network_probe(
    filter: &NetworkFilter,
    bpf: &mut Ebpf,
    btf: &Btf,
) -> crate::error::Result<()> {
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

pub fn attach_process_probe(
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

pub fn convert_process_events(
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
            .ok_or(crate::error::Error::ConfigNotFound)?,
    )?;

    config.insert(0, FileModeFilter::from(filter.file_mode.clone()), 0)?;

    Ok(())
}

pub fn attach_file_probe(
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
        attach_fexit(bpf, btf, "vfs_rename", "vfs_rename")?;
    }

    Ok(())
}

fn convert_file_events(
    producer: &mpsc::Sender<FileEvent>,
    events: &RingBufItem<'_>,
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
            .ok_or(crate::error::Error::FilterNotFound)?,
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

pub fn attach_mem_probe(
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
