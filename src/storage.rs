use rios_cli::load_configuration;
use rios_topology::Lab;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

const VERSION: u32 = 1;
const MAX_STATE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLab {
    version: u32,
    devices: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct StateStore(PathBuf);

#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("state I/O failed for {path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("state file {path} is invalid: {message}")]
    Invalid { path: PathBuf, message: String },
}

impl StateStore {
    pub fn from_path(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn for_topology(topology: &Path) -> Self {
        std::env::var_os("RIOS_STATE_FILE").map_or_else(
            || {
                Self(PathBuf::from(format!(
                    "{}.rios-state.json",
                    topology.display()
                )))
            },
            |path| Self(path.into()),
        )
    }

    pub fn load(&self, lab: &mut Lab) -> Result<(), StorageError> {
        match fs::metadata(&self.0) {
            Ok(metadata) if metadata.len() > MAX_STATE_BYTES => {
                return Err(StorageError::Invalid {
                    path: self.0.clone(),
                    message: format!("file exceeds {MAX_STATE_BYTES} bytes"),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(self.io(source)),
        }
        let input = match fs::read_to_string(&self.0) {
            Ok(input) => input,
            Err(source) => return Err(self.io(source)),
        };
        let stored: StoredLab =
            serde_json::from_str(&input).map_err(|error| StorageError::Invalid {
                path: self.0.clone(),
                message: error.to_string(),
            })?;
        if stored.version != VERSION {
            return Err(StorageError::Invalid {
                path: self.0.clone(),
                message: format!("unsupported version {}", stored.version),
            });
        }
        let mut prepared = Vec::new();
        for (name, config) in stored.devices {
            let Ok(id) = lab.device_id(&name) else {
                continue;
            };
            let mut device = lab
                .device(id)
                .map_err(|error| StorageError::Invalid {
                    path: self.0.clone(),
                    message: error.to_string(),
                })?
                .clone();
            load_configuration(&mut device, &config).map_err(|error| StorageError::Invalid {
                path: self.0.clone(),
                message: format!("device {name}: {error}"),
            })?;
            device.save_config();
            prepared.push((id, device));
        }
        for (id, device) in prepared {
            lab.with_device_mut(id, |current| *current = device)
                .map_err(|error| StorageError::Invalid {
                    path: self.0.clone(),
                    message: error.to_string(),
                })?;
        }
        Ok(())
    }

    pub fn save(&self, lab: &Lab) -> Result<(), StorageError> {
        let devices = lab
            .device_names()
            .filter_map(|(name, id)| {
                lab.device(id)
                    .ok()?
                    .startup_config()
                    .0
                    .as_ref()
                    .map(|config| (name.to_owned(), config.render()))
            })
            .collect();
        let bytes = serde_json::to_vec_pretty(&StoredLab {
            version: VERSION,
            devices,
        })
        .map_err(|error| StorageError::Invalid {
            path: self.0.clone(),
            message: error.to_string(),
        })?;
        if let Some(parent) = self.0.parent().filter(|path| !path.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|source| self.io(source))?;
        }
        let temporary = self.0.with_extension(format!("tmp-{}", std::process::id()));
        let result = (|| {
            let mut file = File::create(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &self.0)?;
            #[cfg(unix)]
            if let Some(parent) = self.0.parent().filter(|path| !path.as_os_str().is_empty()) {
                File::open(parent)?.sync_all()?;
            }
            Ok::<_, io::Error>(())
        })();
        if let Err(source) = result {
            let _ = fs::remove_file(&temporary);
            return Err(self.io(source));
        }
        Ok(())
    }

    fn io(&self, source: io::Error) -> StorageError {
        StorageError::Io {
            path: self.0.clone(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rios_device::Device;

    fn lab() -> (Lab, rios_simulator::DeviceId) {
        let mut lab = Lab::default();
        let device = Device::standalone();
        let id = device.id();
        lab.add_device("R1", device).unwrap();
        (lab, id)
    }

    #[test]
    fn startup_state_round_trips_and_invalid_state_does_not_apply() {
        let directory = std::env::temp_dir().join(format!("rios-state-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("lab.json");
        let store = StateStore::from_path(path.clone());
        let (mut original, id) = lab();
        original
            .with_device_mut(id, |device| {
                device.set_hostname("EDGE").unwrap();
                device.save_config();
            })
            .unwrap();
        store.save(&original).unwrap();

        let (mut restored, restored_id) = lab();
        store.load(&mut restored).unwrap();
        assert_eq!(restored.device(restored_id).unwrap().hostname(), "EDGE");
        assert!(
            restored
                .device(restored_id)
                .unwrap()
                .startup_config()
                .0
                .is_some()
        );

        fs::write(
            &path,
            r#"{"version":1,"devices":{"R1":"hostname 1-invalid\n"}}"#,
        )
        .unwrap();
        let (mut untouched, untouched_id) = lab();
        assert!(store.load(&mut untouched).is_err());
        assert_eq!(untouched.device(untouched_id).unwrap().hostname(), "R1");
        fs::remove_dir_all(directory).unwrap();
    }
}
