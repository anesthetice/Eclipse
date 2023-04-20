/*
The database will hold information such as:
    * RSA encryption keys
    * apostle data (last time it was connected, last ip used to connect, etc...)


*/
use std::path::Path;
use sled;

type BehelitDb = sled::Db;

pub trait BehelitDbMethods {
    const PATH_TO_DATABASE_DIR : &'static str = "behelitDB";
    fn bload<T: AsRef<Path>>(dirpath:T) -> sled::Result<Self>
    where Self: Sized;
    fn bwrite(&self, key:&[u8], value:&[u8]) -> sled::Result<usize>;
    fn bremove(&self, key:&[u8]) -> sled::Result<usize>;
    fn bget_u8<I: AsRef<[u8]>>(&self, key: I) -> sled::Result<Vec<u8>>;
    fn bget_string<I: AsRef<[u8]>>(&self, key: I) -> sled::Result<String>;
}

impl BehelitDbMethods for BehelitDb {
    const PATH_TO_DATABASE_DIR : &'static str = "behelitDB";
    fn bload<T: AsRef<Path>>(dirpath:T) -> sled::Result<Self> {
        return Ok(sled::open(dirpath)?);
    }
    fn bwrite(&self, key:&[u8], value:&[u8]) -> sled::Result<usize> {
        self.insert(key, value)?;
        return self.flush();
    }
    fn bremove(&self, key:&[u8]) -> sled::Result<usize> {
        self.remove(key)?;
        return self.flush();
    }
    fn bget_u8<I: AsRef<[u8]>>(&self, key: I) -> sled::Result<Vec<u8>> {
        match self.get(key)? {
            Some(data) => return Ok(data.as_ref().to_owned()),
            None => return Ok(Vec::new()),
        }
    }
    fn bget_string<I: AsRef<[u8]>>(&self, key: I) -> sled::Result<String> {
        match self.get(key)? {
            Some(data) => return Ok(String::from_utf8_lossy(data.as_ref()).to_string()),
            None => return Ok(String::from("")),
        }
    }
}


#[cfg(test)]
pub mod db_test {
    use core::panic;

    use super::{
        BehelitDb,
        BehelitDbMethods,
    };
    #[test]
    pub fn db_tests() {
        let db = match BehelitDb::bload(BehelitDb::PATH_TO_DATABASE_DIR) {
            Ok(db) => db,
            Err(error) => panic!("{}", error)
        };
        match db.bwrite(b"test-key", b"test") {
            Ok(nb_bytes) => println!("flushed {} bytes after write operation", nb_bytes),
            Err(error) => panic!("{}", error),
        }
        match db.bget_u8(b"test-key") {
            Ok(vec) => assert_eq!(vec.as_slice(), [116, 101, 115, 116]),
            Err(error) => panic!("{}", error),
        }
        match db.bget_string(b"test-key") {
            Ok(string) => assert_eq!(string.as_str(), "test"),
            Err(error) => panic!("{}", error),
        }
        match db.bremove(b"test-key") {
            Ok(nb_bytes) => println!("flushed {} bytes after remove operation", nb_bytes),
            Err(error) => panic!("{}", error),
        }
    }
}