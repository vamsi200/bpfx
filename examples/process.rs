use bpfx::{
    Bpfx, ProcessEvent,
    process::{ProcessFilter, ProcessMask},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(ProcessFilter {
        mask: ProcessMask::ALL,
        ..Default::default()
    })?;

    let _runtime = bpfx.run();

    println!("Watching process activity...");

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
