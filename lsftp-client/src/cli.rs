//! LSFTP CLI implementation

use clap::{Parser, Subcommand};
use crate::client::LsftpClient;
use lsftp_core::Result;
use std::path::PathBuf;

/// LSFTP Client - Secure File Transfer Protocol
#[derive(Parser)]
#[command(name = "lsftp-client")]
#[command(about = "LSFTP client for secure file transfer")]
#[command(version)]
pub struct Cli {
    /// Server address
    #[arg(short, long, default_value = "localhost")]
    pub server: String,

    /// Server port
    #[arg(short, long, default_value = "8443")]
    pub port: u16,

    /// Certificate path
    #[arg(long)]
    pub cert: Option<PathBuf>,

    /// Private key path
    #[arg(long)]
    pub key: Option<PathBuf>,

    /// Hardware device
    #[arg(long)]
    pub hardware: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Connect to server
    Connect {
        /// Server address
        #[arg(value_name = "ADDRESS")]
        address: String,
    },

    /// Upload file
    Upload {
        /// Local file path
        #[arg(value_name = "LOCAL")]
        local: PathBuf,

        /// Remote file path
        #[arg(value_name = "REMOTE")]
        remote: String,
    },

    /// Download file
    Download {
        /// Remote file path
        #[arg(value_name = "REMOTE")]
        remote: String,

        /// Local file path
        #[arg(value_name = "LOCAL")]
        local: PathBuf,
    },

    /// List remote directory
    List {
        /// Remote directory path
        #[arg(value_name = "PATH", default_value = "/")]
        path: String,
    },

    /// Verify file integrity
    Verify {
        /// Remote file path
        #[arg(value_name = "FILE")]
        file: String,
    },
}

/// Run CLI application
pub async fn run_cli() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    if cli.verbose {
        println!("Verbose logging enabled");
    }

    // Create client configuration
    let config = crate::client::ClientConfig {
        server_address: cli.server,
        server_port: cli.port,
        hardware_device: cli.hardware,
        cert_path: cli.cert,
        key_path: cli.key,
        ..Default::default()
    };

    // Create client
    let mut client = LsftpClient::new(config)?;

    // Execute command
    match cli.command {
        Commands::Connect { address } => {
            println!("Connecting to {}", address);
            client.connect().await?;
            println!("Connected successfully");
        }

        Commands::Upload { local, remote } => {
            println!("Uploading {} to {}", local.display(), remote);
            client.connect().await?;
            let bytes = client.upload_file(local.to_str().unwrap(), &remote).await?;
            println!("Uploaded {} bytes", bytes);
        }

        Commands::Download { remote, local } => {
            println!("Downloading {} to {}", remote, local.display());
            client.connect().await?;
            let bytes = client.download_file(&remote, local.to_str().unwrap()).await?;
            println!("Downloaded {} bytes", bytes);
        }

        Commands::List { path } => {
            println!("Listing directory: {}", path);
            client.connect().await?;
            let files = client.list_directory(&path).await?;
            for file in files {
                println!("  {}", file);
            }
        }

        Commands::Verify { file } => {
            println!("Verifying file: {}", file);
            client.connect().await?;
            let is_valid = client.verify_file(&file).await?;
            if is_valid {
                println!("File integrity verified");
            } else {
                println!("File integrity check failed");
            }
        }
    }

    // Disconnect
    client.disconnect().await?;
    Ok(())
}
