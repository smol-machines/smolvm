use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Default, Serialize, Deserialize)]
pub struct Preferences {
    pub runtime: Option<PathBuf>,
    #[serde(default)]
    pub use_cli_session: bool,
}
fn directory() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("com", "smolmachines", "studio")
        .map(|d| d.config_dir().to_path_buf())
        .ok_or("Cannot locate the Studio settings directory.".into())
}
impl Preferences {
    pub fn load() -> Result<Self, String> {
        match fs::read(directory()?.join("settings.json")) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("Cannot read Studio settings: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("Cannot read Studio settings: {e}")),
        }
    }
    pub fn remember_cli(use_cli_session: bool) -> Result<(), String> {
        let mut preferences = Self::load()?;
        preferences.use_cli_session = use_cli_session;
        preferences.save()
    }
    pub fn save(&self) -> Result<(), String> {
        let directory = directory()?;
        fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
        let mut file = tempfile::NamedTempFile::new_in(&directory).map_err(|e| e.to_string())?;
        file.write_all(&serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        file.as_file().sync_all().map_err(|e| e.to_string())?;
        file.persist(directory.join("settings.json"))
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
/// One Studio process owns the rotating OAuth session; independent windows
/// must not spend the same refresh token concurrently.
pub fn instance_lock() -> Result<File, String> {
    let directory = directory()?;
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(directory.join("studio.lock"))
        .map_err(|e| e.to_string())?;
    fs2::FileExt::try_lock_exclusive(&file)
        .map_err(|_| "Smol Studio is already open.".to_string())?;
    Ok(file)
}
