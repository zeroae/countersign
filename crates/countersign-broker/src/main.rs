use countersign_broker::{config::Config, service::Service};
use std::{error::Error, fs};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args_os().skip(1);
    let config_path = args
        .next()
        .filter(|_| args.next().is_none())
        .ok_or("usage: countersign-broker CONFIG.json")?;
    let cfg: Config = serde_json::from_slice(&fs::read(config_path)?)?;
    let app = Service::open(&cfg)?.router();
    if let Some(tls) = cfg.tls {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            tls.certificate_path,
            tls.key_path,
        )
        .await?;
        axum_server::bind_rustls(cfg.listen, config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await?;
    } else {
        if !cfg.listen.ip().is_loopback() {
            return Err(
                "plain HTTP requires a loopback listener behind the Integrator HTTPS ingress"
                    .into(),
            );
        }
        axum::serve(tokio::net::TcpListener::bind(cfg.listen).await?, app).await?;
    }
    Ok(())
}
