#![allow(unused)]
use bpfx::convert::Bpfx;
use bpfx::file::{FileEventMask, FileFilter, UserFileFilter};
use bpfx::network::NetworkFilter;
use bpfx::process::{self, ProcessFilter};
use bpfx::{
    convert::convert_network_events,
    events::EventHeader,
    network::{EventMask, NetworkEvent, PollNetwork, Protocol, ProtocolMask},
};

use futures::{Stream, StreamExt};
use std::os::fd::{self, FromRawFd};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bpfx = Bpfx::new()?;

    // let mut network = bpfx.poll_network(NetworkFilter::default())?;
    // let filter = FileFilter {
    //     event_type: FileEventMask::CLOSE,
    // };

    let filter = FileFilter {
        event_type: FileEventMask::READ,
        file_mode: Some(UserFileFilter::FILE_SOCK),
    };

    let mut exec = bpfx.poll_file(filter)?;

    bpfx.run();

    while let Some(event) = exec.next().await {
        println!("{event:?}");
    }

    Ok(())
}
