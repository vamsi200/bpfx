#![allow(unused)]
use bpfx::{
    convert::convert_network_events,
    network::{NetworkEvent, PollNetwork, Protocol},
};
use futures::{Stream, StreamExt};
use std::os::fd::{self, FromRawFd};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut network = PollNetwork::new()?;

    while let Some(event) = network.next().await {
        match event {
            NetworkEvent::Connect(ev) => match ev.protocol {
                Protocol::Tcp => {
                    println!("{ev:?}");
                }
                _ => {}
            },
            _ => {}
        }
    }

    Ok(())
    // println!("Hello, world!");
}
