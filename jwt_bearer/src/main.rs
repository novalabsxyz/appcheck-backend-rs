use clap::Parser;
use jwt_bearer::{Error, KeypairArgs, PubkeyArgs, TokenArgs, VerifyArgs};

#[derive(Debug, clap::Parser)]
#[clap(version = env!("CARGO_PKG_VERSION"))]
pub struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

impl Cli {
    pub fn run(self) -> Result<(), Error> {
        self.cmd.run()
    }
}

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    Keypair(KeypairArgs),
    Pubkey(PubkeyArgs),
    Token(TokenArgs),
    Verify(VerifyArgs),
}

impl Cmd {
    pub fn run(&self) -> Result<(), Error> {
        match self {
            Self::Keypair(cmd) => cmd.run(),
            Self::Pubkey(cmd) => cmd.run(),
            Self::Token(cmd) => cmd.run(),
            Self::Verify(cmd) => cmd.run(),
        }
    }
}

pub fn main() -> Result<(), Error> {
    Cli::parse().run()
}
