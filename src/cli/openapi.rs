//! OpenAPI export command.

use clap::Args;
use std::fs;
use std::path::PathBuf;
use utoipa::OpenApi;

use smolvm::ApiDoc;

/// Export OpenAPI specification.
#[derive(Args, Debug)]
pub struct OpenapiCmd {
    /// Output file path (defaults to stdout).
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Output format.
    #[arg(short, long, default_value = "json")]
    format: OutputFormat,
}

#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
enum OutputFormat {
    /// JSON format (OpenAPI 3.1)
    #[default]
    Json,
    /// YAML format (OpenAPI 3.1)
    Yaml,
}

impl OpenapiCmd {
    pub fn run(&self) -> Result<(), smolvm::Error> {
        let spec = ApiDoc::openapi();

        let output = match self.format {
            OutputFormat::Json => spec.to_pretty_json().map_err(|e| {
                smolvm::Error::Config(format!("failed to serialize OpenAPI: {}", e))
            })?,
            OutputFormat::Yaml => serde_yaml::to_string(&spec).map_err(|e| {
                smolvm::Error::Config(format!("failed to serialize OpenAPI: {}", e))
            })?,
        };

        match &self.output {
            Some(path) => {
                fs::write(path, &output).map_err(|e| {
                    smolvm::Error::Config(format!("failed to write to {}: {}", path.display(), e))
                })?;
                eprintln!("OpenAPI spec written to {}", path.display());
            }
            None => {
                println!("{}", output);
            }
        }

        Ok(())
    }
}
