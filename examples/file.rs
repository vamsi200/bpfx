use bpfx::{
    Bpfx,
    file::{FileFilter, FileMask, FileTypeFilter},
};
use futures::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut bpfx = Bpfx::new()?;

    // Watch successful opens and renames of regular files.
    let mut events = bpfx.subscribe(FileFilter {
        event_type: FileMask::OPEN | FileMask::RENAME,
        file_mode: FileTypeFilter::FILE_REG,
        ..Default::default()
    })?;

    let _runtime = bpfx.run();

    println!("Watching file events (Ctrl+C to exit)...");

    while let Some(event) = events.next().await {
        if event.failed() {
            continue;
        }

        match event {
            bpfx::file::FileEvent::Open(e) => {
                println!("{e:?}");
            }

            // bpfx::file::FileEvent::Rename(e) => {
            //     println!("{e}");
            // }
            _ => {}
        }
    }

    Ok(())
}
