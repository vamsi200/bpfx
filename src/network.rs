use crate::error::*;
use crate::{
    Bpfx,
    common::EventHeader,
    core::{Subscription, attach_network_probe},
};
use bpfx_common::raw::FilterKey;
use core::fmt;
use futures::Stream;
use std::fmt::Display;
use std::{
    net::IpAddr,
    ops::{BitOr, BitOrAssign},
};
use tokio::sync::mpsc::Sender;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Tcp = 1,
    Udp = 2,
}

impl Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => write!(f, "TCP"),
            Self::Udp => write!(f, "UDP"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SocketEndpoints {
    pub local_ip: IpAddr,
    pub local_port: u16,

    pub remote_ip: IpAddr,
    pub remote_port: u16,
}

impl Display for SocketEndpoints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{}",
            self.local_ip, self.local_port, self.remote_ip, self.remote_port,
        )
    }
}

/// A stream of network events.
///
/// Instances of this type are returned by [`Bpfx::subscribe`] when subscribing
/// with a [`NetworkFilter`].
///
/// Implements [`futures::Stream`], yielding [`NetworkEvent`].
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

/// Bitmask describing which transport protocols should be monitored.
///
/// # Examples
///
/// ```rust
/// # use bpfx::network::ProtocolMask;
/// let protocols = ProtocolMask::TCP | ProtocolMask::UDP;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
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

/// Bitmask describing which network events should generate notifications.
///
/// # Examples
///
/// ```rust
/// # use bpfx::network::NetworkMask;
/// let mask = NetworkMask::CONNECT | NetworkMask::CLOSE;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Copy, Hash)]
pub struct NetworkMask(u8);

impl NetworkMask {
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

impl BitOr for NetworkMask {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for NetworkMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Configures which network events are delivered.
///
/// A `NetworkFilter` controls:
///
/// - which transport protocols are monitored (`protocol_mask`)
/// - which network operations generate events (`event_mask`)
/// - an optional process-based filter (`filter`)
///
/// # Examples
///
/// Monitor TCP connect events from a specific process:
///
/// ```rust
/// # use bpfx::{network::{NetworkFilter, NetworkMask, ProtocolMask}, FilterKey};
/// let filter = NetworkFilter {
///     protocol_mask: ProtocolMask::TCP,
///     event_mask: NetworkMask::CONNECT,
///     filter: FilterKey::Pid(1234),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    pub protocol_mask: ProtocolMask,
    pub event_mask: NetworkMask,
    pub filter: FilterKey,
}

impl Default for NetworkFilter {
    fn default() -> Self {
        Self {
            protocol_mask: ProtocolMask::ALL,
            event_mask: NetworkMask::ALL,
            filter: FilterKey::None,
        }
    }
}

/// Internal registration state for a network event subscription.
///
/// Stores the active filter and the channel used to deliver events
/// to the corresponding event stream.
#[derive(Debug, Clone)]
pub(crate) struct NetworkRegister {
    pub filter: NetworkFilter,
    pub tx: Sender<NetworkEvent>,
}

impl Subscription for NetworkFilter {
    type Event = NetworkEvent;
    type Stream = PollNetwork;

    fn subscribe(self, bpfx: &mut Bpfx) -> Result<Self::Stream> {
        let (tx, rx) = tokio::sync::mpsc::channel(bpfx.config.channel_capacity);

        let reg = NetworkRegister { filter: self, tx };

        attach_network_probe(&reg.filter, &mut bpfx.bpf, &bpfx.btf)?;

        bpfx.network = Some(reg);

        Ok(PollNetwork { rx })
    }
}

impl NetworkFilter {
    pub const ALL: Self = Self {
        protocol_mask: ProtocolMask::ALL,
        event_mask: NetworkMask::ALL,
        filter: FilterKey::None,
    };

    pub const TCP: Self = Self {
        protocol_mask: ProtocolMask::TCP,
        event_mask: NetworkMask::ALL,
        filter: FilterKey::None,
    };

    pub const UDP: Self = Self {
        protocol_mask: ProtocolMask::UDP,
        event_mask: NetworkMask::ALL,
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

impl Display for ConnectEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} CONNECT {} -> {}",
            self.header, self.protocol, self.endpoints, self.retval,
        )
    }
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

impl Display for AcceptEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ACCEPT {}",
            self.header, self.protocol, self.endpoints,
        )
    }
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

impl Display for CloseEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} CLOSE {}",
            self.header, self.protocol, self.endpoints,
        )
    }
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

impl Display for BindEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} BIND {} -> {}",
            self.header, self.protocol, self.endpoints, self.retval,
        )
    }
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

impl Display for ListenEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} LISTEN {} -> {}",
            self.header, self.protocol, self.endpoints, self.retval,
        )
    }
}

/// A network socket event.
///
/// This enum groups all network-related events emitted by bpfx, such as
/// connection establishment, socket binding, listening, accepting, and
/// socket closure.
///
/// Use pattern matching or the provided helper methods to inspect the
/// underlying event.
///
/// This enum is marked as `non_exhaustive` and may gain additional variants
/// in future releases.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    Connect(ConnectEvent),
    Accept(AcceptEvent),
    Close(CloseEvent),
    Bind(BindEvent),
    Listen(ListenEvent),
}

impl Display for NetworkEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect(e) => e.fmt(f),
            Self::Accept(e) => e.fmt(f),
            Self::Close(e) => e.fmt(f),
            Self::Bind(e) => e.fmt(f),
            Self::Listen(e) => e.fmt(f),
        }
    }
}

impl NetworkEvent {
    fn protocol(&self) -> Protocol {
        match self {
            Self::Connect(e) => e.protocol,
            Self::Accept(e) => e.protocol,
            Self::Close(e) => e.protocol,
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
