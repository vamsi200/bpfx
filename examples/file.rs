use bpfx::{Bpfx, FileEvent, file::FileFilter};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    // Watch successful opens and renames of regular files.
    let mut events = bpfx.subscribe(FileFilter::ALL)?;

    bpfx.run();

    println!("Watching file events (Ctrl+C to exit)...");

    while let Some(event) = events.next().await {
        if event.failed() {
            continue;
        }

        match event {
            FileEvent::Open(e) => {
                if e.file_name().contains("passwd") || e.file_path.contains("passwd") {
                    println!("{e}");
                }
            }

            FileEvent::Rename(e) => {
                println!("{e}");
            }
            _ => {}
        }
    }

    Ok(())
}
