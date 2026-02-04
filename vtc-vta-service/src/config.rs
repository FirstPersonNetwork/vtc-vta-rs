use crate::error::AppError;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub store: StoreConfig,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub format: LogFormat,
}

#[derive(Debug, Deserialize)]
pub struct StoreConfig {
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

#[derive(Debug, Default, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("data/vta")
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: LogFormat::default(),
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
        }
    }
}

impl AppConfig {
    pub fn load() -> Result<Self, AppError> {
        let path = std::env::var("VTA_CONFIG_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("config.toml"));

        let mut config = if path.exists() {
            let contents = std::fs::read_to_string(&path).map_err(AppError::Io)?;
            toml::from_str::<AppConfig>(&contents)
                .map_err(|e| AppError::Config(format!("failed to parse {}: {e}", path.display())))?
        } else {
            AppConfig {
                server: ServerConfig::default(),
                log: LogConfig::default(),
                store: StoreConfig::default(),
            }
        };

        // Apply env var overrides
        if let Ok(host) = std::env::var("VTA_SERVER_HOST") {
            config.server.host = host;
        }
        if let Ok(port) = std::env::var("VTA_SERVER_PORT") {
            config.server.port = port
                .parse()
                .map_err(|e| AppError::Config(format!("invalid VTA_SERVER_PORT: {e}")))?;
        }
        if let Ok(level) = std::env::var("VTA_LOG_LEVEL") {
            config.log.level = level;
        }
        if let Ok(format) = std::env::var("VTA_LOG_FORMAT") {
            config.log.format = match format.to_lowercase().as_str() {
                "json" => LogFormat::Json,
                "text" => LogFormat::Text,
                other => {
                    return Err(AppError::Config(format!(
                        "invalid VTA_LOG_FORMAT '{other}', expected 'text' or 'json'"
                    )));
                }
            };
        }
        if let Ok(data_dir) = std::env::var("VTA_STORE_DATA_DIR") {
            config.store.data_dir = PathBuf::from(data_dir);
        }

        Ok(config)
    }
}
