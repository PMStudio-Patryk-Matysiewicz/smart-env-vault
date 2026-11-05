use crate::{DeviceKey, KeyError};
use secrecy::{ExposeSecret, SecretString};
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

pub trait KeyStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError>;
    fn save(&self, key: &DeviceKey) -> Result<(), KeyError>;
    fn delete(&self) -> Result<(), KeyError>;
}

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

pub struct KeychainStore {
    username: String,
}

impl KeychainStore {
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

pub struct PassphraseFileStore {
    path: PathBuf,
    passphrase: SecretString,
}

impl PassphraseFileStore {
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
        std::fs::write(&self.path, bytes).map_err(|_| KeyError::Storage)
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