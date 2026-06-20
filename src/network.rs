#![allow(unused)]

use crate::events::EventHeader;
use std::net::IpAddr;

// expectation:
// while let Some(event) = monitor.next().await {
//     match event {
//         NetworkEvent::Connect(e) => {
//             println!(
//                 "{} ({}) connected to {}:{}",
//                 e.header.comm,
//                 e.header.pid,
//                 e.dst_ip,
//                 e.dst_port
//             );
//         }
//
//         NetworkEvent::Accept(e) => {}
//
//         NetworkEvent::Close(e) => {}
//     }
// }

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ConnectEvent {
    pub header: EventHeader,

    pub protocol: Protocol,

    pub src_ip: IpAddr,
    pub src_port: u16,

    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub struct AcceptEvent {
    pub header: EventHeader,

    pub protocol: Protocol,

    pub local_ip: IpAddr,
    pub local_port: u16,

    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

#[derive(Debug, Clone)]
pub struct CloseEvent {
    pub header: EventHeader,

    pub protocol: Protocol,

    pub src_ip: IpAddr,
    pub src_port: u16,

    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    Connect(ConnectEvent),
    Accept(AcceptEvent),
    Close(CloseEvent),
}
