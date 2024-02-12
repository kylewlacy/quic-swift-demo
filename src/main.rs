use std::net::SocketAddr;

use clap::Parser;

#[derive(Debug, Parser)]
struct Args {
    #[clap(long, default_value = "0.0.0.0:4567")]
    bind: SocketAddr,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt().compact().without_time().init();

    let args = Args::parse();

    color_eyre::install()?;

    let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut tls = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, priv_key)?;
    tls.alpn_protocols = vec!["demo".as_bytes().to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(tls));

    let endpoint = quinn::Endpoint::server(server_config, args.bind)?;
    tracing::info!("Listening");
    loop {
        if let Some(conn) = endpoint.accept().await {
            tracing::info!("New connection");

            tokio::task::spawn(async move {
                let conn = conn.await.inspect_err(|err| {
                    tracing::error!("Connection error: {err:#}");
                })?;

                let (initial_tx, initial_rx) = conn.accept_bi().await.inspect_err(|err| {
                    tracing::error!("Failed to accept new initial stream: {err:#}");
                })?;

                tracing::info!(
                    tx_id = initial_tx.id().index(),
                    rx_id = initial_rx.id().index(),
                    "Accepted initial stream",
                );

                let (mut tx, mut rx) = conn.accept_bi().await.inspect_err(|err| {
                    tracing::error!("Failed to accept new connection: {err:#}");
                })?;
                tracing::info!(
                    tx_id = tx.id().index(),
                    rx_id = rx.id().index(),
                    "Received new stream",
                );

                tokio::task::spawn(async move {
                    let mut buf = vec![0; 4];
                    rx.read_exact(&mut buf).await.inspect_err(|err| {
                        tracing::error!("Failed to read from stream: {err:#}");
                    })?;
                    tracing::info!("Received: {buf:?}");

                    tx.write_all(b"Hello, world!")
                        .await
                        .inspect_err(|err| tracing::error!("Failed to write to stream: {err:#}"))?;
                    tx.finish().await.inspect_err(|err| {
                        tracing::error!("Failed to finish stream: {err:#}");
                    })?;

                    tracing::info!("Wrote to stream");

                    match rx.read_to_end(0).await {
                        Ok(_) => {}
                        Err(error) => {
                            tracing::error!("Failed to read end of stream: {error:#}");
                            let _ = rx.stop(0u8.into()).inspect_err(|err| {
                                tracing::warn!("Failed to manually stop stream: {err:#}");
                            });
                        }
                    }

                    tracing::info!("Closed stream");

                    let (mut next_tx, mut next) = conn.accept_bi().await.inspect_err(|err| {
                        tracing::error!("Failed to accept new stream: {err:#}");
                    })?;
                    next_tx.finish().await.inspect_err(|err| {
                        tracing::error!("Failed to finish stream: {err:#}");
                    })?;

                    tracing::info!("Accepted next stream");

                    let data = next.read_to_end(4).await.inspect_err(|err| {
                        tracing::error!("Failed to read from stream: {err:#}");
                    })?;
                    tracing::info!("Received: {data:?}");

                    tracing::info!("Connection finished");
                    conn.close(0u8.into(), b"Done");

                    eyre::Ok(())
                });

                eyre::Ok(())
            });
        };
    }
}
