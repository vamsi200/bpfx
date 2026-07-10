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
    Tcp = 1,
    Udp = 2,
}

#[derive(Debug, Clone)]
pub struct SocketEndpoints {
    pub local_ip: IpAddr,
    pub local_port: u16,

    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

/// Emitted after the kernel completes processing a successful connect() call.
/// Generated from `tcp_v4_connect()` and `tcp_v6_connect()`.
#[derive(Debug, Clone)]
pub struct ConnectEvent {
    pub header: EventHeader,
    pub protocol: Protocol,
    pub endpoints: SocketEndpoints,
}

/// Emitted after the kernel accepts an incoming TCP connection.
/// Generated from `inet_csk_accept()`.
/// This event is only emitted for TCP.
#[derive(Debug, Clone)]
pub struct AcceptEvent {
    pub header: EventHeader,
    pub protocol: Protocol,
    pub endpoints: SocketEndpoints,
}

/// Emitted when the kernel closes a socket.
/// Generated from `tcp_close()` for TCP sockets and
/// `udp_destroy_sock()` for UDP sockets.
#[derive(Debug, Clone)]
pub struct CloseEvent {
    pub header: EventHeader,
    pub protocol: Protocol,
    pub endpoints: SocketEndpoints,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    Connect(ConnectEvent),
    Accept(AcceptEvent),
    Close(CloseEvent),
}
