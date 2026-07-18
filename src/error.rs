use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    #[error(transparent)]
    Btf(#[from] aya::BtfError),

    #[error("failed to load eBPF program")]
    Load(#[from] aya::EbpfError),

    #[error("failed to attach eBPF program")]
    Attach(#[from] aya::programs::ProgramError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Map(#[from] aya::maps::MapError),

    #[error("unsupported kernel feature")]
    Unsupported,

    #[error("invalid filter")]
    InvalidFilter,

    #[error("failed to retrieve eBPF program")]
    ProgramAccess,

    #[error("no active event subscriptions remain")]
    NoActiveSubscriptions,

    #[error("failed to access FILTER map")]
    FilterMapAccess,

    #[error("failed to access CONFIG map")]
    ConfigMapAccess,

    #[error("failed to access EVENTS ring buffer")]
    EventsMapAccess,
}

pub type Result<T> = std::result::Result<T, Error>;
