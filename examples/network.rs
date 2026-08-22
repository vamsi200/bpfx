use bpfx::{Bpfx, NetworkEvent, network::NetworkFilter};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(NetworkFilter::ALL)?;

    let _runtime = bpfx.run();

    println!("Watching network activity (Ctrl+C to exit)...");

    while let Some(event) = events.next().await {
        match event {
            NetworkEvent::Connect(e) => println!("{e}"),
            NetworkEvent::Accept(e) => println!("{e}"),
            NetworkEvent::Bind(e) => println!("{e}"),
            NetworkEvent::Listen(e) => println!("{e}"),
            NetworkEvent::Close(e) => println!("{e}"),
            _ => {}
        }
    }

    Ok(())
}
