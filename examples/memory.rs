use bpfx::{Bpfx, MemoryEvent, memory::MemoryFilter};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(MemoryFilter::ALL)?;

    let _runtime = bpfx.run();

    println!("Watching virtual memory mappings (Ctrl+C to exit)...");

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
