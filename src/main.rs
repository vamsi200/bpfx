#![allow(unused)]
use bpfx::Bpfx;
use bpfx::file::{FileEvent, FileFilter, FileType};
use bpfx::memory::{MemoryEvent, MemoryFilter, MemoryMask};
use bpfx::network::NetworkFilter;
use bpfx::process::{self, ProcessFilter};
use bpfx::{
    common::EventHeader,
    network::{NetworkEvent, PollNetwork, Protocol, ProtocolMask},
};

use bpfx_common::raw::{FileModeFilter, FilterKey};
use futures::{Stream, StreamExt};
use std::os::fd::{self, FromRawFd};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let mut bpfx = Bpfx::new().unwrap();

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

    let mut exec = bpfx.subscribe(NetworkFilter::default()).unwrap();

    bpfx.run();

    while let Some(event) = exec.next().await {
        println!("{event:?}");
    }

    Ok(())
}
