use thiserror;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Btf(#[from] aya::BtfError),

    #[error("failed to load eBPF program")]
    Load(#[from] aya::EbpfError),

    #[error("failed to attach probe")]
    Attach(#[from] aya::programs::ProgramError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Map(#[from] aya::maps::MapError),

    #[error("unsupported kernel feature")]
    Unsupported,

    #[error("invalid filter")]
    InvalidFilter,

    #[error("failed to get mutable reference to program")]
    ProgramNotFound,

    //Change the names of the maps.
    #[error("failed to get mutable on FILTER ArrayMap")]
    FilterNotFound,

    #[error("failed to get mutable on CONFIG HashMap")]
    ConfigNotFound,

    #[error("failed to take EVENTS map")]
    EventNotFound,
}

pub type Result<T> = std::result::Result<T, Error>;
