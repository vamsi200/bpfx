#![allow(unused)]
use crate::network::NetworkEvent::*;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};

use crate::{
    events::EventHeader,
    network::{AcceptEvent, CloseEvent, ConnectEvent, NetworkEvent, SocketEndpoints},
};
use anyhow::Result;
use aya::{
    Btf, Ebpf, include_bytes_aligned,
    maps::RingBuf,
    programs::{FEntry, FExit, KProbe},
};
use aya_log::EbpfLogger;
use bpfx_common::raw::*;
use tokio::sync::mpsc::{self, error::TrySendError};

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

// Read and convert the raw event structs to structured and then send to channel..
pub async fn convert_network_events(producer: mpsc::Sender<NetworkEvent>) -> Result<()> {
    env_logger::init();

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../target/bpfel-unknown-none/release/bpfx-ebpf"
    ))?;

    EbpfLogger::init(&mut bpf)?;
    let btf = Btf::from_sys_fs()?;

    let prog: &mut FExit = bpf.program_mut("udp_connect").unwrap().try_into()?;
    prog.load("udp_connect", &btf)?;
    prog.attach()?;

    let prog: &mut FExit = bpf.program_mut("udpv6_connect").unwrap().try_into()?;
    prog.load("udpv6_connect", &btf)?;
    prog.attach()?;

    let prog: &mut FExit = bpf.program_mut("udp_destroy_sock").unwrap().try_into()?;
    prog.load("udp_destroy_sock", &btf)?;
    prog.attach()?;

    let prog: &mut FExit = bpf.program_mut("tcp_v4_connect").unwrap().try_into()?;
    prog.load("tcp_v4_connect", &btf)?;
    prog.attach()?;

    let prog: &mut FExit = bpf.program_mut("tcp_v6_connect").unwrap().try_into()?;
    prog.load("tcp_v6_connect", &btf)?;
    prog.attach()?;

    let prog: &mut KProbe = bpf.program_mut("inet_csk_accept").unwrap().try_into()?;
    prog.load()?;
    prog.attach("inet_csk_accept", 0)?;

    let prog: &mut FExit = bpf.program_mut("tcp_close").unwrap().try_into()?;
    prog.load("tcp_close", &btf)?;
    prog.attach()?;

    println!("[INFO] Running..");

    if bpf.map("EVENTS").is_none() {
        println!("EVENTS not found");
    }
    let events_map = bpf
        .take_map("EVENTS")
        .ok_or_else(|| anyhow::anyhow!("Faild to get map"))?;

    let mut ring_buffer = RingBuf::try_from(events_map)?;

    loop {
        if let Some(events) = ring_buffer.next() {
            let ptr = events.as_ptr();
            let event = unsafe { ptr::read(ptr as *const PendingConnect) };

            match event.protocol {
                RawProtocol::Tcp => match event.header.event_type {
                    EventType::Connect => {
                        let protocol = crate::network::Protocol::Tcp;
                        let (header, endpoints) = parse_network_event(&event);

                        match producer.try_send(network_event!(
                            Connect,
                            ConnectEvent,
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
                    }

                    EventType::Accept => {
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
                    }

                    EventType::Close => {
                        let (header, endpoints) = parse_network_event(&event);
                        let protocol = crate::network::Protocol::Tcp;
                        match producer.try_send(network_event!(
                            Close, CloseEvent, header, protocol, endpoints
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
                },

                RawProtocol::Udp => match event.header.event_type {
                    EventType::Connect => {
                        let protocol = crate::network::Protocol::Udp;
                        let (header, endpoints) = parse_network_event(&event);

                        match producer.try_send(network_event!(
                            Connect,
                            ConnectEvent,
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
                    }
                    EventType::Accept => {
                        let (header, endpoints) = parse_network_event(&event);
                        let protocol = crate::network::Protocol::Udp;
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
                    }

                    EventType::Close => {
                        let (header, endpoints) = parse_network_event(&event);
                        let protocol = crate::network::Protocol::Udp;
                        match producer.try_send(network_event!(
                            Close, CloseEvent, header, protocol, endpoints
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
                },
            }
        }
    }

    Ok(())
}
