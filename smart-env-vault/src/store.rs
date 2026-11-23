use crate::{DeviceKey, KeyError};
use secrecy::{ExposeSecret, SecretString};
use std::{
    fs::OpenOptions,
    path::{Path, PathBuf},
    sync::Mutex,
};
use uuid::Uuid;

/// Persistent storage for the [`DeviceKey`].
///
/// Implementations: [`KeychainStore`] (default), [`PassphraseFileStore`]
/// (headless fallback), [`MemoryStore`] (tests).
pub trait KeyStore {
    /// Loads the saved key; `Ok(None)` if nothing has been saved yet.
    fn load(&self) -> Result<Option<DeviceKey>, KeyError>;
    /// Saves the key, replacing any previous one.
    fn save(&self, key: &DeviceKey) -> Result<(), KeyError>;
    /// Removes the saved key. Succeeds if there was nothing to remove.
    fn delete(&self) -> Result<(), KeyError>;
}

/// In-memory [`KeyStore`] for tests. Lost when the process ends.
#[derive(Default)]
pub struct MemoryStore {
    key: Mutex<Option<secrecy::SecretString>>,
}

impl KeyStore for MemoryStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        self.key
            .lock()
            .map_err(|_| KeyError::Storage)?
            .as_ref()
            .map(DeviceKey::from_secret)
            .transpose()
    }

    fn save(&self, key: &DeviceKey) -> Result<(), KeyError> {
        *self.key.lock().map_err(|_| KeyError::Storage)? = Some(key.to_secret());
        Ok(())
    }

    fn delete(&self) -> Result<(), KeyError> {
        *self.key.lock().map_err(|_| KeyError::Storage)? = None;
        Ok(())
    }
}

/// [`KeyStore`] backed by the system keychain: macOS Keychain, Windows
/// Credential Manager or Linux Secret Service (via the `keyring` crate).
///
/// Lets daily work happen without a password prompt.
pub struct KeychainStore {
    username: String,
}

impl KeychainStore {
    /// Creates a store for the keychain entry `smart-env-vault` / `username`.
    pub fn new(username: String) -> Self {
        Self { username }
    }

    fn entry(&self) -> Result<keyring::Entry, KeyError> {
        keyring::Entry::new("smart-env-vault", &self.username)
            .map_err(|_| KeyError::KeychainUnavailable)
    }
}

impl KeyStore for KeychainStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        match self.entry()?.get_password() {
            Ok(secret) => DeviceKey::from_secret(&SecretString::from(secret))
                .map(Some)
                .map_err(|_| KeyError::InvalidDeviceKey),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(KeyError::KeychainUnavailable),
        }
    }

    fn save(&self, key: &DeviceKey) -> Result<(), KeyError> {
        self.entry()?
            .set_password(key.to_secret().expose_secret())
            .map_err(|_| KeyError::KeychainUnavailable)
    }

    fn delete(&self) -> Result<(), KeyError> {
        match self.entry()?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(KeyError::KeychainUnavailable),
        }
    }
}

/// [`KeyStore`] for the unlocked device key in passphrase mode: the Linux
/// kernel keyring of the user (`@u`), entry `smart-env:device-seed`, expiring
/// after a time-to-live (ADR-002). Never written to disk.
///
/// Shared by all sessions and terminal tabs of the user until it expires or
/// is deleted (`smart-env lock`). Outside Linux every call returns
/// [`KeyError::SessionUnavailable`].
pub struct KernelKeyringStore {
    description: String,
    ttl: std::time::Duration,
}

impl KernelKeyringStore {
    /// Store for `smart-env:device-seed`, expiring `ttl` after each save.
    pub fn new(ttl: std::time::Duration) -> Self {
        Self::named("smart-env:device-seed", ttl)
    }

    /// Store under another entry name (tests, so they never touch the real
    /// unlocked key).
    pub fn named(description: &str, ttl: std::time::Duration) -> Self {
        Self {
            description: description.to_owned(),
            ttl,
        }
    }
}

#[cfg(target_os = "linux")]
impl KernelKeyringStore {
    fn keyring() -> Result<linux_keyutils::KeyRing, KeyError> {
        linux_keyutils::KeyRing::from_special_id(linux_keyutils::KeyRingIdentifier::User, false)
            .map_err(|_| KeyError::SessionUnavailable)
    }

    /// The entry, `None` if it does not exist, expired or was revoked.
    fn find(&self) -> Result<Option<linux_keyutils::Key>, KeyError> {
        use linux_keyutils::KeyError as Kernel;
        match Self::keyring()?.search(&self.description) {
            Ok(key) => Ok(Some(key)),
            Err(Kernel::KeyDoesNotExist | Kernel::KeyExpired | Kernel::KeyRevoked) => Ok(None),
            Err(_) => Err(KeyError::SessionUnavailable),
        }
    }
}

#[cfg(target_os = "linux")]
impl KeyStore for KernelKeyringStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        use linux_keyutils::KeyError as Kernel;
        let Some(key) = self.find()? else {
            return Ok(None);
        };
        let bytes = match key.read_to_vec() {
            Ok(bytes) => zeroize::Zeroizing::new(bytes),
            // Expired or revoked between the search and the read.
            Err(Kernel::KeyDoesNotExist | Kernel::KeyExpired | Kernel::KeyRevoked) => {
                return Ok(None);
            }
            Err(_) => return Err(KeyError::SessionUnavailable),
        };
        let text = std::str::from_utf8(&bytes).map_err(|_| KeyError::InvalidDeviceKey)?;
        DeviceKey::from_secret(&SecretString::from(text)).map(Some)
    }

    fn save(&self, key: &DeviceKey) -> Result<(), KeyError> {
        // `add_key` replaces an entry with the same description.
        let entry = Self::keyring()?
            .add_key(&self.description, key.to_secret().expose_secret())
            .map_err(|_| KeyError::SessionUnavailable)?;
        let seconds = usize::try_from(self.ttl.as_secs().max(1)).unwrap_or(usize::MAX);
        if entry.set_timeout(seconds).is_err() {
            // Never leave an entry without expiry behind.
            let _ = entry.invalidate();
            return Err(KeyError::SessionUnavailable);
        }
        Ok(())
    }

    fn delete(&self) -> Result<(), KeyError> {
        match self.find()? {
            Some(entry) => entry.invalidate().map_err(|_| KeyError::SessionUnavailable),
            None => Ok(()),
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl KeyStore for KernelKeyringStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        let _ = (&self.description, self.ttl);
        Err(KeyError::SessionUnavailable)
    }

    fn save(&self, _key: &DeviceKey) -> Result<(), KeyError> {
        Err(KeyError::SessionUnavailable)
    }

    fn delete(&self) -> Result<(), KeyError> {
        Err(KeyError::SessionUnavailable)
    }
}

/// Fallback [`KeyStore`] for machines without a keychain (headless Linux, SSH):
/// the key is kept in a file encrypted with a passphrase (`age` scrypt).
pub struct PassphraseFileStore {
    path: PathBuf,
    passphrase: SecretString,
}

impl PassphraseFileStore {
    /// Creates a store for the file at `path`, protected by `passphrase`.
    /// Nothing is read or written until the first call.
    pub fn new(path: impl Into<PathBuf>, passphrase: SecretString) -> Self {
        Self {
            path: path.into(),
            passphrase,
        }
    }

    fn read_secret(&self) -> Result<SecretString, KeyError> {
        let bytes = std::fs::read(&self.path).map_err(|_| KeyError::Storage)?;
        let decryptor = age::Decryptor::new(std::io::Cursor::new(bytes))
            .map_err(|_| KeyError::WrongPassphrase)?;
        let identity = age::scrypt::Identity::new(self.passphrase.clone());
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|_| KeyError::WrongPassphrase)?;
        let mut secret = String::new();
        std::io::Read::read_to_string(&mut reader, &mut secret).map_err(|_| KeyError::Storage)?;
        Ok(SecretString::from(secret))
    }

    fn write_secret(&self, secret: &SecretString) -> Result<(), KeyError> {
        let encryptor = age::Encryptor::with_user_passphrase(self.passphrase.clone());
        let mut bytes = Vec::new();
        let mut writer = encryptor
            .wrap_output(&mut bytes)
            .map_err(|_| KeyError::Storage)?;
        std::io::Write::write_all(&mut writer, secret.expose_secret().as_bytes())
            .map_err(|_| KeyError::Storage)?;
        writer.finish().map_err(|_| KeyError::Storage)?;

        let temp_path = self
            .path
            .with_added_extension(format!("tmp-{}", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);

        let mut temp_file = options.open(&temp_path).map_err(|_| KeyError::Storage)?;

        if let Err(error) =
            std::io::Write::write_all(&mut temp_file, &bytes).and_then(|_| temp_file.sync_all())
        {
            let _ = std::fs::remove_file(&temp_path);
            let _ = error;
            return Err(KeyError::Storage);
        }
        drop(temp_file);

        #[cfg(windows)]
        if self.path.exists() {
            std::fs::remove_file(&self.path).map_err(|_| KeyError::Storage)?;
        }

        if let Err(error) = std::fs::rename(&temp_path, &self.path) {
            let _ = std::fs::remove_file(&temp_path);
            let _ = error;
            return Err(KeyError::Storage);
        }
        Ok(())
    }
}

impl KeyStore for PassphraseFileStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError> {
        if !Path::new(&self.path).exists() {
            return Ok(None);
        }
        DeviceKey::from_secret(&self.read_secret()?)
            .map(Some)
            .map_err(|_| KeyError::InvalidDeviceKey)
    }

    fn save(&self, key: &DeviceKey) -> Result<(), KeyError> {
        self.write_secret(&key.to_secret())
    }

    fn delete(&self) -> Result<(), KeyError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(KeyError::Storage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn store_in(directory: &TempDir, passphrase: &str) -> PassphraseFileStore {
        PassphraseFileStore::new(
            directory.path().join("device-key.age"),
            SecretString::from(passphrase),
        )
    }

    #[test]
    fn save_and_load_should_round_trip_device_key() {
        let directory = TempDir::new().unwrap();
        let store = store_in(&directory, "correct horse battery staple");
        let key = DeviceKey::generate();

        store.save(&key).unwrap();
        let loaded = store.load().unwrap().unwrap();

        assert_eq!(loaded.public(), key.public());
    }

    #[test]
    fn load_should_return_none_before_first_save() {
        let directory = TempDir::new().unwrap();
        let store = store_in(&directory, "correct horse battery staple");

        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn load_should_return_wrong_passphrase_for_a_different_passphrase() {
        let directory = TempDir::new().unwrap();
        let store = store_in(&directory, "correct horse battery staple");
        store.save(&DeviceKey::generate()).unwrap();

        let wrong_store = PassphraseFileStore::new(
            directory.path().join("device-key.age"),
            SecretString::from("wrong"),
        );

        assert_eq!(wrong_store.load().unwrap_err(), KeyError::WrongPassphrase);
    }

    #[test]
    fn delete_should_remove_key_and_be_idempotent() {
        let directory = TempDir::new().unwrap();
        let store = store_in(&directory, "correct horse battery staple");
        store.save(&DeviceKey::generate()).unwrap();

        store.delete().unwrap();
        store.delete().unwrap();

        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn save_should_replace_an_existing_device_key() {
        let directory = TempDir::new().unwrap();
        let store = store_in(&directory, "correct horse battery staple");
        let first = DeviceKey::generate();
        let replacement = DeviceKey::generate();

        store.save(&first).unwrap();
        store.save(&replacement).unwrap();
        let loaded = store.load().unwrap().unwrap();

        assert_eq!(loaded.public(), replacement.public());
    }

    #[cfg(unix)]
    #[test]
    fn save_should_create_key_file_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TempDir::new().unwrap();
        let store = store_in(&directory, "correct horse battery staple");
        store.save(&DeviceKey::generate()).unwrap();
        let mode = std::fs::metadata(directory.path().join("device-key.age"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);
    }
}
