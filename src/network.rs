#![allow(unused)]

use crate::{convert::convert_network_events, events::EventHeader};
use futures::{Stream, StreamExt};
use std::{net::IpAddr, pin::Pin, sync::mpsc};

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

// TODO: Change the name
pub struct PollNetwork {
    rx: tokio::sync::mpsc::Receiver<NetworkEvent>,
}

impl Stream for PollNetwork {
    type Item = NetworkEvent;
    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let pn = self.get_mut();
        pn.rx.poll_recv(cx)
    }
}

impl PollNetwork {
    pub fn new() -> anyhow::Result<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<NetworkEvent>(1024);
        tokio::spawn(async move {
            convert_network_events(tx).await.unwrap();
        });
        Ok(Self { rx })
    }
}

/// Emitted after the kernel completes processing a successful connect() call.
/// Generated from `tcp_v4_connect()` and `tcp_v6_connect()` fpr TCP.
/// Generated from `udp_connect()` and `udpv6_connect()` fpr TCP.
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

//NOTE: In future maybe include udp_sendmsg, udpv6_sendmsg for udp?
