use countersign_broker::{config::Config, service::Service};
use std::{error::Error, ffi::OsStr, fs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (recover, path) = match args.as_slice() {
        [path] => (false, path),
        [flag, path] if flag == OsStr::new("--recover-backup") => (true, path),
        _ => return Err("usage: countersign-broker [--recover-backup] CONFIG.json".into()),
    };
    let cfg: Config = serde_json::from_slice(&fs::read(path)?)?;
    if recover {
        return Service::recover_backup(&cfg);
    }
    if let Some(tls) = &cfg.tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &tls.certificate_path,
            &tls.key_path,
        )
        .await?;
        let app = Service::open(&cfg)?.router();
        axum_server::bind_rustls(cfg.listen, tls)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        if !cfg.listen.ip().is_loopback() {
            return Err(
                "plain HTTP requires a loopback listener behind the Integrator HTTPS ingress"
                    .into(),
            );
        }
        let listen = tokio::net::TcpListener::bind(cfg.listen).await?;
        axum::serve(listen, Service::open(&cfg)?.router()).await?;
    }
    Ok(())
}
