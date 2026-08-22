use bpfx::{Bpfx, ProcessEvent, process::ProcessFilter};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(ProcessFilter::ALL)?;

    let _runtime = bpfx.run();

    println!("Watching process activity (Ctrl+C to exit)...");

    while let Some(event) = events.next().await {
        match event {
            ProcessEvent::Start(s) => println!("{s}"),
            ProcessEvent::Exit(s) => println!("{s}"),
            ProcessEvent::Fork(s) => println!("{s}"),
            _ => {}
        }
    }

    Ok(())
}
