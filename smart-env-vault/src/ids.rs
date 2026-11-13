use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

/// Defines a UUID newtype. Each id kind is a separate type, so passing a
/// `KeyId` where an `EnvironmentId` is expected does not compile.
macro_rules! id_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        ///
        /// Random UUID v4 generated on the client, stored as a 16-byte `BLOB`.
        /// Stable for the lifetime of the object and part of the [`Aad`](crate::Aad).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(uuid::Uuid);

        impl $name {
            /// Generates a new random identifier (UUID v4).
            pub fn new() -> Self {
                Self(uuid::Uuid::new_v4())
            }

            /// The 16 raw bytes, as used in the [`Aad`](crate::Aad) and the database.
            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                Ok(ToSqlOutput::Borrowed(ValueRef::Blob(self.as_bytes())))
            }
        }

        impl FromSql for $name {
            fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                let bytes: [u8; 16] =
                    value
                        .as_blob()?
                        .try_into()
                        .map_err(|_| FromSqlError::InvalidBlobSize {
                            expected_size: 16,
                            blob_size: value.as_blob().map_or(0, <[u8]>::len),
                        })?;
                Ok(Self(uuid::Uuid::from_bytes(bytes)))
            }
        }
    };
}

id_type!(
    /// Identifier of a whole vault (one per database file).
    VaultId
);
id_type!(
    /// Identifier of a project, e.g. `payments`.
    ProjectId
);
id_type!(
    /// Identifier of an environment, e.g. `payments/dev`. Each environment has its own DEK.
    EnvironmentId
);
id_type!(
    /// Stable identity of a secret. Survives renaming, unlike its [`VarName`](crate::VarName).
    KeyId
);
id_type!(
    /// Identifier of a vault recipient: a device, the recovery key or a machine key.
    RecipientId
);

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn ids_are_unique() {
        assert_ne!(KeyId::new(), KeyId::new());
    }

    #[test]
    fn id_round_trips_through_sqlite_as_16_byte_blob() {
        let db = Connection::open_in_memory().unwrap();
        let id = KeyId::new();
        let (back, len): (KeyId, i64) = db
            .query_row("SELECT ?1, length(?1)", [id], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })
            .unwrap();
        assert_eq!(back, id);
        assert_eq!(len, 16);
    }

    #[test]
    fn id_rejects_blob_of_wrong_length() {
        let db = Connection::open_in_memory().unwrap();
        let result: rusqlite::Result<KeyId> = db.query_row("SELECT x'0102'", [], |row| row.get(0));
        assert!(result.is_err());
    }
}
