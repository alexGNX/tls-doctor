use clap::{ArgGroup, Args, Parser, Subcommand};
use std::path::PathBuf;

/// Top-level CLI with subcommands.
#[derive(Parser, Debug)]
#[command(name = "tls-doctor", version, about = "TLS inspector and tooling")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Diagnose a live server or a PEM bundle
    Diag(DiagArgs),
    /// Scaffold a complete bundle from a leaf certificate file
    Scaffold(ScaffoldArgs),
}

#[derive(Args, Debug)]
#[command(group(ArgGroup::new("input").required(true).args(["server", "file"])))]
pub struct DiagArgs {
    /// Domain name or IP of the server to connect to
    #[arg(short = 's', long = "server")]
    pub server: Option<String>,

    /// PEM bundle file (one or more concatenated certificates)
    #[arg(short = 'f', long = "file")]
    pub file: Option<PathBuf>,

    /// Port of the server (default: 443)
    #[arg(short = 'p', long = "port", default_value_t = 443)]
    pub port: u16,

    /// Disable certificate verification (like -verify 0). Useful for inspecting invalid chains.
    #[arg(long)]
    pub insecure: bool,
}

#[derive(Args, Debug)]
pub struct ScaffoldArgs {
    /// Input leaf certificate file (PEM or DER)
    #[arg(short = 'i', long = "input", required = true)]
    pub input: PathBuf,

    /// Output bundle destination (PEM); will be created/overwritten
    #[arg(short = 'o', long = "output", required = true)]
    pub output: PathBuf,
}
