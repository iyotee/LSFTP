use clap::Parser;
use lsftp_core::{TransportConfig, QuicServerTransport, Result};
use std::path::PathBuf;

/// LSFTP Server - Secure File Transfer Protocol
#[derive(Parser)]
#[command(name = "lsftp-server")]
#[command(about = "LSFTP server for secure file transfer")]
#[command(version)]
pub struct Cli {
    /// Configuration file
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Server address
    #[arg(short, long, default_value = "0.0.0.0")]
    pub address: String,

    /// Server port
    #[arg(short, long, default_value = "8443")]
    pub port: u16,

    /// Certificate path
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Private key path
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    if cli.verbose {
        println!("Verbose logging enabled");
    }

    // Create server configuration
    let config = TransportConfig {
        server_address: cli.address,
        server_port: cli.port,
        cert_path: cli.cert.map(|p| p.to_string_lossy().to_string()),
        key_path: cli.key.map(|p| p.to_string_lossy().to_string()),
        ..Default::default()
    };

    // Create and start server
    let mut server = QuicServerTransport::new(config)?;
    
    println!("Starting LSFTP server...");
    server.start().await?;
    
    println!("LSFTP server started successfully");
    
    // Keep server running
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    }
}
