#![allow(unused)]
use crate::file::{
    FileCloseEvent, FileDeleteEvent, FileEvent, FileEventMask, FileFilter, FileOpenEvent,
    FileReadEvent, FileRenameEvent, FileType, FileWriteEvent, PollFile, UserFileFilter,
};
use crate::network::{
    EventMask, NetworkEvent::*, NetworkFilter, PollNetwork, Protocol, ProtocolMask,
};
use crate::process::ProcessEvent::*;
use crate::process::*;
use crate::process::{
    self, PollProcess, ProcessEvent, ProcessEventMask, ProcessExitEvent, ProcessFilter,
};
use crate::{
    events::EventHeader,
    network::{AcceptEvent, CloseEvent, ConnectEvent, NetworkEvent, SocketEndpoints},
};
use anyhow::Result;
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
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::time::error::Elapsed;

#[derive(Debug, Clone)]
struct NetworkRegister {
    filter: NetworkFilter,
    tx: Sender<NetworkEvent>,
}

#[derive(Debug)]
struct ProcessRegister {
    filter: ProcessFilter,
    tx: Sender<ProcessEvent>,
}

#[derive(Debug)]
struct FileRegister {
    filter: FileFilter,
    tx: Sender<FileEvent>,
}

pub struct Bpfx {
    bpf: Ebpf,
    btf: Btf,
    ringbuf: RingBuf<MapData>,
    network: Option<NetworkRegister>,
    process: Option<ProcessRegister>,
    file: Option<FileRegister>,
}

impl Bpfx {
    pub fn new() -> anyhow::Result<Self> {
        env_logger::init();

        let mut bpf = Ebpf::load(include_bytes_aligned!(
            "../target/bpfel-unknown-none/release/bpfx-ebpf"
        ))?;

        let btf = Btf::from_sys_fs()?;
        EbpfLogger::init(&mut bpf)?;

        let events = bpf
            .take_map("EVENTS")
            .ok_or_else(|| anyhow::anyhow!("EVENTS not found"))?;

        let ringbuf = RingBuf::try_from(events)?;
        Ok(Self {
            bpf,
            btf,
            ringbuf,
            network: None,
            process: None,
            file: None,
        })
    }

    pub fn poll_network(&mut self, filter: NetworkFilter) -> anyhow::Result<PollNetwork> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<NetworkEvent>(1024);
        let nr = NetworkRegister { filter, tx };
        attach_network_probe(&nr.filter, &mut self.bpf, &self.btf);
        self.network = Some(nr);

        Ok(PollNetwork { rx })
    }

    pub fn poll_process(&mut self, filter: ProcessFilter) -> anyhow::Result<PollProcess> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<ProcessEvent>(1024);
        let pr = ProcessRegister { filter, tx };
        attach_process_probe(&pr.filter, &mut self.bpf, &self.btf);
        self.process = Some(pr);
        Ok(PollProcess { rx })
    }

    pub fn poll_file(&mut self, filter: FileFilter) -> anyhow::Result<PollFile> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FileEvent>(1024);
        let fr = FileRegister { filter, tx };
        attach_file_probe(&fr.filter, &mut self.bpf, &self.btf);
        self.file = Some(fr);

        Ok(PollFile { rx })
    }

    pub fn run(self) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        tokio::spawn(async move { self.run_boy().await })
    }

    pub async fn run_boy(mut self) -> Result<()> {
        loop {
            if let Some(events) = self.ringbuf.next() {
                if let Some(nr) = &self.network {
                    convert_network_events(&mut self.bpf, &self.btf, &nr.tx, &nr.filter, &events)?;
                }

                if let Some(pr) = &self.process {
                    convert_process_events(&mut self.bpf, &self.btf, &pr.tx, &pr.filter, &events)?;
                }

                if let Some(pr) = &self.file {
                    convert_file_events(&mut self.bpf, &self.btf, &pr.tx, &pr.filter, &events)?;
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
    ($variant: ident, $ty: ident, $header: expr, $filename: expr, $file_type: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            filename: $filename,
            file_type: $file_type,
        })
    };

    ($variant: ident, $ty: ident, $header: expr, $old_filename: expr, $new_filename: expr, $file_type: expr) => {
        FileEvent::$variant($ty {
            header: $header,
            old_filename: $old_filename,
            new_filename: $new_filename,
            file_type: $file_type,
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
) -> Result<()> {
    let prog: &mut FExit = bpf.program_mut(prog_name).unwrap().try_into()?; // dont unwrap here??
    prog.load(func_name, btf)?;
    prog.attach()?;
    Ok(())
}

fn attach_kprobe(bpf: &mut Ebpf, prog_name: &'static str, symbol: &'static str) -> Result<()> {
    let prog: &mut KProbe = bpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load()?;
    prog.attach(symbol, 0)?;
    Ok(())
}

fn attach_fentry(
    bpf: &mut Ebpf,
    btf: &Btf,
    prog_name: &'static str,
    symbol: &'static str,
) -> Result<()> {
    let prog: &mut FEntry = bpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load(prog_name, &btf)?;
    prog.attach()?;
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut Ebpf,
    prog_name: &'static str,
    category: &'static str,
    tracepoint: &'static str,
) -> Result<()> {
    let prog: &mut TracePoint = bpf.program_mut(prog_name).unwrap().try_into()?;
    prog.load()?;
    prog.attach(category, tracepoint)?;
    Ok(())
}

fn handle_connect(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) -> Result<()> {
    let (header, endpoints) = parse_network_event(&event);

    match event.protocol {
        RawProtocol::Tcp => {
            match producer.try_send(network_event!(
                Connect,
                ConnectEvent,
                header,
                Protocol::Tcp,
                endpoints
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
                }
            }
        }

        RawProtocol::Udp => {
            match producer.try_send(network_event!(
                Connect,
                ConnectEvent,
                header,
                Protocol::Udp,
                endpoints
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
                }
            }
        }
    }

    Ok(())
}

fn handle_tcp_accept(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) -> Result<()> {
    let (header, endpoints) = parse_network_event(&event);
    let protocol = crate::network::Protocol::Tcp;
    match producer.try_send(network_event!(
        Accept,
        AcceptEvent,
        header,
        protocol,
        endpoints
    )) {
        Ok(()) => {}
        Err(TrySendError::Full(val)) => {
            eprintln!("Failed to send to channel")
        }
        Err(TrySendError::Closed(val)) => {
            eprintln!("Channel Closed :/");
        }
    }
    Ok(())
}

fn handle_close(event: &PendingConnect, producer: &mpsc::Sender<NetworkEvent>) -> Result<()> {
    let (header, endpoints) = parse_network_event(&event);

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
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
                }
            }
        }
    }

    Ok(())
}

fn attach_network_probe(filter: &NetworkFilter, bpf: &mut Ebpf, btf: &Btf) {
    if filter.protocols.contains(&ProtocolMask::TCP) && filter.events.contains(&EventMask::CONNECT)
    {
        for probe in TCP_CONNECT {
            attach_fexit(bpf, &btf, probe.0, probe.1);
        }
    }

    if filter.protocols.contains(&ProtocolMask::TCP) && filter.events.contains(&EventMask::ACCEPT) {
        for probe in TCP_ACCEPT {
            attach_kprobe(bpf, probe.0, probe.1);
        }
    }

    if filter.protocols.contains(&ProtocolMask::TCP) && filter.events.contains(&EventMask::CLOSE) {
        attach_kprobe(bpf, TCP_CLOSE.0, TCP_CLOSE.1);
    }

    if filter.protocols.contains(&ProtocolMask::UDP) && filter.events.contains(&EventMask::CONNECT)
    {
        for probe in UDP_CONNECT {
            attach_fexit(bpf, &btf, probe.0, probe.1);
        }
    }

    if filter.protocols.contains(&ProtocolMask::UDP) && filter.events.contains(&EventMask::CLOSE) {
        attach_fexit(bpf, &btf, UDP_CLOSE.0, UDP_CLOSE.1);
    }
}

// Read and convert the raw event structs to structured and then send to channel..
pub fn convert_network_events(
    bpf: &mut Ebpf,
    btf: &Btf,
    producer: &mpsc::Sender<NetworkEvent>,
    filter: &NetworkFilter,
    events: &RingBufItem<'_>,
) -> Result<()> {
    let ptr = events.as_ptr();
    let event = unsafe { ptr::read(ptr as *const PendingConnect) };

    match event.header.event_type {
        EventType::Connect => handle_connect(&event, &producer)?,
        EventType::Accept => handle_tcp_accept(&event, &producer)?,
        EventType::Close => handle_close(&event, &producer)?,
        _ => {}
    }

    Ok(())
}

fn attach_process_probe(filter: &ProcessFilter, bpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    if filter.event_type.contains(&ProcessEventMask::START) {
        attach_tracepoint(bpf, "sched_process_exec", "sched", "sched_process_exec")?;
    }

    if filter.event_type.contains(&ProcessEventMask::FORK) {
        attach_tracepoint(bpf, "sched_process_fork", "sched", "sched_process_fork")?;
    }

    if filter.event_type.contains(&ProcessEventMask::EXIT) {
        attach_fentry(bpf, &btf, "do_group_exit", "do_group_exit")?;
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
    bpf: &mut Ebpf,
    btf: &Btf,
    producer: &mpsc::Sender<ProcessEvent>,
    filter: &ProcessFilter,
    events: &RingBufItem<'_>,
) -> anyhow::Result<()> {
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
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
                }
            };
        }
        _ => {}
    }

    Ok(())
}

fn write_to_map(bpf: &mut Ebpf, filter: &FileFilter) {
    use aya::maps::HashMap;

    let mut config: HashMap<_, u32, FileModeFilter> =
        HashMap::try_from(bpf.map_mut("CONFIG").unwrap()).unwrap();

    config
        .insert(0, FileModeFilter::from(filter.file_mode.clone()), 0)
        .unwrap();
}

fn attach_file_probe(filter: &FileFilter, bpf: &mut Ebpf, btf: &Btf) {
    if filter.event_type.contains(&FileEventMask::OPEN) {
        write_to_map(bpf, filter);
        attach_fexit(bpf, btf, "vfs_open", "vfs_open").unwrap();
    }

    if filter.event_type.contains(&FileEventMask::CLOSE) {
        write_to_map(bpf, filter);
        attach_fentry(bpf, btf, "filp_close", "filp_close").unwrap();
    }

    if filter.event_type.contains(&FileEventMask::READ) {
        attach_fexit(bpf, btf, "vfs_read", "vfs_read").unwrap();
    }

    if filter.event_type.contains(&FileEventMask::WRITE) {
        write_to_map(bpf, filter);
        attach_fexit(bpf, btf, "vfs_write", "vfs_write").unwrap();
    }

    if filter.event_type.contains(&FileEventMask::DELETE) {
        write_to_map(bpf, filter);
        attach_fentry(bpf, btf, "vfs_unlink", "vfs_unlink").unwrap();
    }

    if filter.event_type.contains(&FileEventMask::RENAME) {
        write_to_map(bpf, filter);
        attach_fentry(bpf, btf, "vfs_rename", "vfs_rename").unwrap();
    }
}

fn convert_file_events(
    bpf: &mut Ebpf,
    btf: &Btf,
    producer: &mpsc::Sender<FileEvent>,
    filter: &FileFilter,
    events: &RingBufItem<'_>,
) -> anyhow::Result<()> {
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
                FileOpen,
                FileOpenEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode)
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                FileClose,
                FileCloseEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode)
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                FileRead,
                FileReadEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode)
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                FileWrite,
                FileWriteEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode)
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                FileDelete,
                FileDeleteEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.filename[..path_len]).into_owned(),
                FileType::from(event.file_mode)
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
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
                FileRename,
                FileRenameEvent,
                convert_header(event.header),
                String::from_utf8_lossy(&event.old_filename[..old_path_len]).into_owned(),
                String::from_utf8_lossy(&event.new_filename[..new_path_len]).into_owned(),
                FileType::from(event.file_mode)
            )) {
                Ok(()) => {}
                Err(TrySendError::Full(val)) => {
                    eprintln!("Failed to send to channel")
                }
                Err(TrySendError::Closed(val)) => {
                    eprintln!("Channel Closed :/");
                }
            }
        }

        _ => {}
    }

    Ok(())
}
