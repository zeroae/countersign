#[cfg(target_os = "linux")]
mod runtime;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0)?;
    nix::sys::prctl::set_dumpable(false)?;
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["grant-worker"] {
        // Before the async runtime exists: the worker sandbox is applied by a
        // process with one thread that has read no input.
        return runtime::grant_worker();
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(runtime::run(&args))
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!(
        "Gateway worker isolation requires a Linux host. Run the Gateway container on this platform."
    );
    std::process::exit(1);
}
