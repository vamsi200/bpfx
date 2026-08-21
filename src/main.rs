#![allow(unused)]
use bpfx::file::{FileEvent, FileFilter, FileType};
use bpfx::memory::{MemoryEvent, MemoryFilter, MemoryMask};
use bpfx::network::NetworkFilter;
use bpfx::process::{self, ProcessFilter};
use bpfx::{Bpfx, FileMask, NetworkMask, ProcessMask};
use bpfx::{
    common::EventHeader,
    network::{NetworkEvent, PollNetwork, Protocol, ProtocolMask},
};

use bpfx_common::raw::{FileModeFilter, FilterKey};
use futures::{Stream, StreamExt};
use std::os::fd::{self, FromRawFd};
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use log::{Level, debug, error, info, log_enabled};

    let mut bpfx = Bpfx::new()?;

    let process_filter = ProcessFilter {
        mask: ProcessMask::ALL,
        ..Default::default()
    };

    let file_filter = FileFilter {
        event_type: FileMask::READ | FileMask::OPEN,
        ..Default::default()
    };

    let network_filter = NetworkFilter {
        event_mask: NetworkMask::ACCEPT,
        ..Default::default()
    };

    let mut process_events = bpfx.subscribe(process_filter)?;
    let mut file_events = bpfx.subscribe(file_filter)?;
    let mut network_events = bpfx.subscribe(network_filter)?;

    let runtime = bpfx.run();

    while let Some(event) = file_events.next().await {
        if event.failed() {
            continue;
        }

        match event {
            bpfx::file::FileEvent::Open(e) => {
                println!("{e:?}");
            }

            bpfx::file::FileEvent::Rename(e) => {
                println!("{e}");
            }

            _ => {}
        }
    }
    Ok(())
}
