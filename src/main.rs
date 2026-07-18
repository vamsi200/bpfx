#![allow(unused)]
use bpfx::file::{FileEvent, FileFilter, FileType};
use bpfx::memory::{MemoryEvent, MemoryFilter, MemoryMask};
use bpfx::network::NetworkFilter;
use bpfx::process::{self, ProcessFilter};
use bpfx::{Bpfx, BpfxConfig, FileMask};
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
    let config = BpfxConfig {
        channel_capacity: 2000,
    };

    let mut bpfx = Bpfx::with_config(config)?;
    let _events = bpfx.subscribe(ProcessFilter::ALL)?;

    let runtime = bpfx.run();

    runtime.await??;

    Ok(())
}
