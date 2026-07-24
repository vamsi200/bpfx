>Note: WIP, api's may change.

# bpfx

`bpfx` provides a simple API for monitoring process, file, memory, and network
events without writing eBPF programs yourself.

## Features

- Process lifecycle events
- File operation events
- Memory mapping events
- Network socket events
- Event filtering by PID, UID, GID, etc.
- Async `Stream`-based API
- Built on Aya

## Requirements

- Linux with eBPF support
- **Root privileges** (or the required capabilities)
  
## Installation

```bash
cargo add bpfx futures tokio
```

>Or clone this repo and use it directly by adding :

```bash
[dependencies]
bpfx = { path = "/path/to/repo/bpfx" }
tokio = { version = "1", features = ["full"] }
futures = "0.3"
```

## Quick Start

```rust
use bpfx::{Bpfx, process::ProcessFilter};
use futures::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(ProcessFilter::ALL)?;

    let _runtime = bpfx.run();

    while let Some(event) = events.next().await {
        println!("{event:?}");
    }

    Ok(())
}
```

# Examples

## Process Events

Monitor process start events.

```rust
use bpfx::{Bpfx, process::ProcessFilter};
use futures::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(ProcessFilter::START)?;

    let _runtime = bpfx.run();

    while let Some(event) = events.next().await {
        println!("{event:?}");
    }

   Ok(())
}
```

## File Events

Monitor file opens and renames.

```rust
use bpfx::{
    Bpfx,
    file::{FileFilter, FileMask},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(FileFilter {
        event_type: FileMask::OPEN | FileMask::RENAME,
        ..Default::default()
    })?;

  let _runtime = bpfx.run();

  while let Some(event) = events.next().await {
      println!("{event:?}");
  }

  Ok(())
}
```

## Network Events

Monitor TCP connect events.

```rust
use bpfx::{
    Bpfx,
    network::{NetworkFilter, NetworkMask, ProtocolMask},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let mut bpfx = Bpfx::new()?;

  let mut events = bpfx.subscribe(NetworkFilter {
      protocol_mask: ProtocolMask::TCP,
      event_mask: NetworkMask::CONNECT,
      ..Default::default()
  })?;

  let _runtime = bpfx.run();

  while let Some(event) = events.next().await {
      println!("{event:?}");
  }

  Ok(())
}
```

## Memory Events

Monitor memory mappings.

```rust
use bpfx::{
    Bpfx,
    memory::{MemoryFilter, MemoryMask},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
  let mut bpfx = Bpfx::new()?;

  let mut events = bpfx.subscribe(MemoryFilter {
      mask: MemoryMask::MMAP,
      ..Default::default()
  })?;

  let _runtime = bpfx.run();

  while let Some(event) = events.next().await {
      println!("{event:?}");
  }

  Ok(())
}
```

## Filtering by Process

Only receive events from a specific PID.

```rust
use bpfx::{
    Bpfx,
    FilterKey,
    process::ProcessFilter,
};

let filter = ProcessFilter {
    filter: FilterKey::Pid(1234),
    ..ProcessFilter::ALL
};
```

## License

Licensed under the MIT License.
