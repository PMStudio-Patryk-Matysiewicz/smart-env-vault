use rusqlite::types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef};

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(uuid::Uuid);

        impl $name {
            pub fn new() -> Self {
                todo!()
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                todo!()
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl ToSql for $name {
            fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
                todo!()
            }
        }

        impl FromSql for $name {
            fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
                todo!()
            }
        }
    };
}

id_type!(VaultId);
id_type!(ProjectId);
id_type!(EnvironmentId);
id_type!(KeyId);

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
        let result: rusqlite::Result<KeyId> =
            db.query_row("SELECT x'0102'", [], |row| row.get(0));
        assert!(result.is_err());
    }
}
