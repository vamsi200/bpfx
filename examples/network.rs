use bpfx::{
    Bpfx, NetworkEvent,
    network::{NetworkFilter, NetworkMask, ProtocolMask},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    let mut events = bpfx.subscribe(NetworkFilter {
        protocol_mask: ProtocolMask::TCP,
        event_mask: NetworkMask::CONNECT,
        ..Default::default()
    })?;

    let _runtime = bpfx.run();

    println!("Watching network activity...\n");

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
