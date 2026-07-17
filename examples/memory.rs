use bpfx::{
    Bpfx, MemoryEvent,
    memory::{MemoryFilter, MemoryMask},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(MemoryFilter {
        mask: MemoryMask::ALL,
        ..Default::default()
    })?;

    let _runtime = bpfx.run();

    println!("Watching virtual memory mappings...");

    while let Some(event) = events.next().await {
        if event.is_kernel_thread() {
            continue;
        }

        match &event {
            MemoryEvent::MemoryMap(mmap) => {
                println!("{mmap}");
            }

            MemoryEvent::MemoryUnMap(unmap) => {
                println!("{unmap}");
            }

            _ => {}
        }
    }

    Ok(())
}
