pub trait KeyStore {
    fn load(&self) -> Result<Option<DeviceKey>, KeyError>;
    fn save(&self, key: &DeviceKey) -> Result<(), KeyError>;
    fn delete(&self) -> Result<(), KeyError>;
}