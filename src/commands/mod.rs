//! Command implementations.
//!
//! Each submodule exposes a `run(...)` entry point invoked by
//! [`crate::run`]. With the exception of [`doctor`] (which performs real tool
//! probing), the commands are **stubs** that print a clear "not yet implemented"
//! notice through the [`crate::ui::Ui`] layer and return `Ok(())`. Each carries
//! a `//! TODO` contract describing the behavior the next phase must implement.

pub mod check;
pub mod completion;
pub mod deps;
pub mod doctor;
pub mod edit;
pub mod init;
pub mod recipient;
