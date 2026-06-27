use anyhow::Result;
use clap::{Parser, Subcommand};
use owo_colors::OwoColorize;

#[derive(Parser)]
#[command(name = "sopsy")]
#[command(version)]
#[command(about = "The missing developer experience for SOPS")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check local setup
    Doctor,

    /// Initialize Sopsy in this repo
    Init,

    /// Edit an encrypted secrets file
    Edit {
        file: std::path::PathBuf,

        /// Extra args passed to sops after --
        #[arg(last = true)]
        sops_args: Vec<String>,
    },
}

fn main() -> Result<()> {
    color_eyre::install().ok();

    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor => doctor(),
        Commands::Init => {
            println!("{}", "sopsy init (tbd)".yellow());
            Ok(())
        }
        Commands::Edit { file, sops_args } => {
            println!("{} {}", "editing".green(), file.display());
            println!("extra sops args: {:?}", sops_args);
            Ok(())
        }
    }
}

fn doctor() -> Result<()> {
    for tool in ["git", "sops", "age-plugin-se"] {
        match which::which(tool) {
            Ok(path) => println!("{} {} {}", "✔".green(), tool, path.display()),
            Err(_) => println!("{} {} not found", "ｘ".red(), tool),
        }
    }

    Ok(())
}
