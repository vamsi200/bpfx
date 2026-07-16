#![allow(unused)]
use bpfx::convert::Bpfx;
use bpfx::file::{FileEvent, FileEventMask, FileFilter, UserFileFilter};
use bpfx::memory::{MemoryEvent, MemoryFilter, MemoryMask};
use bpfx::network::NetworkFilter;
use bpfx::process::{self, ProcessFilter};
use bpfx::{
    convert::convert_network_events,
    events::EventHeader,
    network::{EventMask, NetworkEvent, PollNetwork, Protocol, ProtocolMask},
};

use bpfx_common::raw::FilterKey;
use futures::{Stream, StreamExt};
use std::os::fd::{self, FromRawFd};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bpfx = Bpfx::new()?;

    // let mut network = bpfx.poll_network(NetworkFilter::default())?;
    // let filter = FileFilter {
    //     event_type: FileEventMask::CLOSE,
    //     file_mode: UserFileFilter::default()
    // };

    let filter = MemoryFilter {
        mask: MemoryMask::MMAP,
        filter: FilterKey::Pid(1958),
    };

    // let filter = ProcessFilter {
    // event_type: ProcessEventMask::default()
    // };

    // let filter = NetworkFilter {
    //     protocols: ProtocolMask::TCP,
    //     events: EventMask::LISTEN,
    // };

    let mut exec = bpfx.poll_memory(filter)?;

    bpfx.run();

    while let Some(event) = exec.next().await {
        println!("{:?}", event);
    }

    Ok(())
}
