#![allow(unused)]

use crate::events::EventHeader;
use bpfx_common::raw::FilterKey;
use futures::{Stream, StreamExt};
use std::{
    env::JoinPathsError,
    net::IpAddr,
    ops::{BitAnd, BitOr, BitOrAssign},
    pin::Pin,
    sync::mpsc,
};

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
    pub rx: tokio::sync::mpsc::Receiver<NetworkEvent>,
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

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct ProtocolMask(u8);

impl ProtocolMask {
    pub const TCP: Self = Self(1 << 0);
    pub const UDP: Self = Self(1 << 1);

    pub const ALL: Self = Self(Self::TCP.0 | Self::UDP.0);

    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for ProtocolMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ProtocolMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub struct EventMask(u8);

impl EventMask {
    pub const CONNECT: Self = Self(1 << 0);
    pub const ACCEPT: Self = Self(1 << 1);
    pub const CLOSE: Self = Self(1 << 2);
    pub const BIND: Self = Self(1 << 3);
    pub const LISTEN: Self = Self(1 << 4);

    pub const ALL: Self =
        Self(Self::CONNECT.0 | Self::ACCEPT.0 | Self::CLOSE.0 | Self::BIND.0 | Self::LISTEN.0);

    pub fn contains(&self, other: &Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for EventMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for EventMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

//TODO: Change these names as well
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    pub protocol_mask: ProtocolMask,
    pub event_mask: EventMask,
    pub filter: FilterKey,
}

impl Default for NetworkFilter {
    fn default() -> Self {
        Self {
            protocol_mask: ProtocolMask::ALL,
            event_mask: EventMask::ALL,
            filter: FilterKey::None,
        }
    }
}

impl NetworkFilter {
    pub const ALL: Self = Self {
        protocol_mask: ProtocolMask::ALL,
        event_mask: EventMask::ALL,
        filter: FilterKey::None,
    };

    pub const TCP: Self = Self {
        protocol_mask: ProtocolMask::TCP,
        event_mask: EventMask::ALL,
        filter: FilterKey::None,
    };

    pub const UDP: Self = Self {
        protocol_mask: ProtocolMask::UDP,
        event_mask: EventMask::ALL,
        filter: FilterKey::None,
    };
}

/// Emitted after the kernel completes processing a successful connect() call.
/// Generated from `tcp_v4_connect()` and `tcp_v6_connect()` fpr TCP.
/// Generated from `udp_connect()` and `udpv6_connect()` for UDP.
#[derive(Debug, Clone)]
pub struct ConnectEvent {
    pub header: EventHeader,
    pub protocol: Protocol,
    pub endpoints: SocketEndpoints,
    pub retval: i32,
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

/// Emitted when the kernel completes binding a socket to a local address.
/// Generated from the `inet_bind` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a socket bind operation.
#[derive(Debug, Clone)]
pub struct BindEvent {
    pub header: EventHeader,
    pub protocol: Protocol,
    pub endpoints: SocketEndpoints,
    pub retval: i32,
}

/// Emitted when the kernel completes putting a socket into the listening state.
/// Generated from the `inet_listen` fexit hook.
/// This event is emitted immediately after the kernel finishes processing
/// a listen operation.
#[derive(Debug, Clone)]
pub struct ListenEvent {
    pub header: EventHeader,
    pub protocol: Protocol,
    pub endpoints: SocketEndpoints,
    pub retval: i32,
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    Connect(ConnectEvent),
    Accept(AcceptEvent),
    Close(CloseEvent),
    Bind(BindEvent),
    Listen(ListenEvent),
}

impl NetworkEvent {
    fn protocol(&self) -> Protocol {
        match self {
            Self::Connect(e) => e.protocol,
            Self::Accept(e) => e.protocol,
            Self::Close(e) => e.protocol,
            Self::Bind(e) => e.protocol,
            Self::Bind(e) => e.protocol,
            Self::Listen(e) => e.protocol,
        }
    }

    pub fn is_tcp(&self) -> bool {
        self.protocol() == Protocol::Tcp
    }

    pub fn is_udp(&self) -> bool {
        self.protocol() == Protocol::Udp
    }

    pub fn header(&self) -> &EventHeader {
        match self {
            Self::Connect(e) => &e.header,
            Self::Accept(e) => &e.header,
            Self::Close(e) => &e.header,
            Self::Bind(e) => &e.header,
            Self::Listen(e) => &e.header,
        }
    }

    pub fn endpoints(&self) -> &SocketEndpoints {
        match self {
            Self::Connect(e) => &e.endpoints,
            Self::Accept(e) => &e.endpoints,
            Self::Close(e) => &e.endpoints,
            Self::Bind(e) => &e.endpoints,
            Self::Listen(e) => &e.endpoints,
        }
    }
}

//NOTE: In future maybe include udp_sendmsg, udpv6_sendmsg for udp?
