use bpfx::{
    Bpfx,
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
        println!("{event}");
    }

    Ok(())
}
