//! Error types for the `sopsy` library.
//!
//! The crate uses [`thiserror`] to define a structured [`Error`] enum for the
//! library surface, while the binary and higher-level orchestration code use
//! [`anyhow`]/[`color_eyre`] for ergonomic context-rich reporting. Downstream
//! command implementations should return [`Result`] and convert lower-level
//! failures into the appropriate [`Error`] variant.

use std::path::PathBuf;

/// Convenient result alias used throughout the library.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that `sopsy` can produce.
///
/// Variants are intentionally coarse-grained for now; later phases will add
/// finer-grained context as command logic is implemented.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A required external binary (e.g. `sops`, `age`, `age-plugin-se`, `git`)
    /// could not be found on `PATH`.
    #[error("required tool `{0}` was not found on PATH")]
    ToolNotFound(String),

    /// An external process exited with a non-zero status.
    #[error("`{tool}` exited with status {code}: {message}")]
    ProcessFailed {
        /// The tool that was invoked.
        tool: String,
        /// The exit code reported by the process (or -1 if terminated by signal).
        code: i32,
        /// Captured stderr or a human-readable summary.
        message: String,
    },

    /// An interactive prompt was requested while running in non-interactive
    /// mode. The caller should supply the corresponding command-line flag.
    #[error(
        "interactive input required for `{prompt}` but running in --non-interactive mode; pass {flag} instead"
    )]
    NonInteractive {
        /// Human-readable description of what was being asked.
        prompt: String,
        /// The flag the user should pass to provide the value non-interactively.
        flag: String,
    },

    /// A configuration or data file could not be found.
    #[error("file not found: {0}")]
    FileNotFound(PathBuf),

    /// A configuration file failed to parse.
    #[error("failed to parse {path}: {source}")]
    Parse {
        /// The file that failed to parse.
        path: PathBuf,
        /// The underlying YAML error.
        #[source]
        source: serde_yaml_ng::Error,
    },

    /// A validation/health check failed (used by `check` / `doctor`).
    #[error("validation failed: {0}")]
    Validation(String),

    /// The current directory is not inside a git repository.
    #[error("not inside a git repository")]
    NotAGitRepo,

    /// A feature is only available on macOS (e.g. Secure Enclave identities).
    #[error("{0} is only supported on macOS")]
    UnsupportedPlatform(String),

    /// Wrapper for I/O errors.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Wrapper for YAML (de)serialization errors not tied to a specific file.
    #[error(transparent)]
    Yaml(#[from] serde_yaml_ng::Error),

    /// Catch-all for errors bubbled up from `anyhow`-based helpers.
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
