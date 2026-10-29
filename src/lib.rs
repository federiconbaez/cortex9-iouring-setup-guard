//! Guard userspace de flags de `io_uring_setup` + catálogo residual.

pub mod catalog;
pub mod flags;
pub mod guard;
pub mod setup;

pub use catalog::{embedded_catalog, CatalogEntry};
pub use guard::{Decision, Guard};
pub use setup::{try_setup, SetupResult};
