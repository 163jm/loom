use anyhow::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use crate::config::Config;

pub fn init(config: &Config) -> Result<()> {
    let level = config.log_level.as_deref().unwrap_or("info").to_string();

    let log_file = config
        .log_file
        .as_deref()
        .unwrap_or("/tmp/loom.log")
        .to_string();

    let env_filter = EnvFilter::try_new(&level).unwrap_or_else(|_| EnvFilter::new("info"));

    // File appender (non-rolling, single file)
    let file_appender = tracing_appender::rolling::never(
        std::path::Path::new(&log_file)
            .parent()
            .unwrap_or(std::path::Path::new("/tmp")),
        std::path::Path::new(&log_file)
            .file_name()
            .unwrap_or(std::ffi::OsStr::new("loom.log")),
    );

    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Keep the guard alive for the lifetime of the program by leaking it
    std::mem::forget(_guard);

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(false);

    let stdout_layer = fmt::layer()
        .with_writer(std::io::stdout)
        .with_ansi(true)
        .with_target(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer)
        .with(stdout_layer)
        .init();

    Ok(())
}
