use serde::{Serialize, Deserialize};
use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    XChaCha12Poly1305, XNonce
};
use time::OffsetDateTime;

#[derive(Debug, Clone, PartialEq)]
pub struct Ledger {
    pub entries: Vec<LedgerEntry>
}

impl Ledger {
    pub fn encrypt(&self, cipher: &XChaCha12Poly1305) -> Self {
        Self {entries : self.entries.iter().map(|ledger_entry| {ledger_entry.encrypt(cipher)}).collect() }
    }
    pub fn decrypt(&self, cipher: &XChaCha12Poly1305) -> Self {
        Self {entries : self.entries.iter().map(|ledger_entry| {ledger_entry.decrypt(cipher)}).collect() }
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn push_back(&mut self, entry: LedgerEntry) {
        self.entries.push(entry);
    }
    pub fn extend(&mut self, other: Ledger) {
        self.entries.extend(other.entries.into_iter())
    }
    /// exports all of the timestamps in the ledger
    /// is used essentially for the 'fetch_missing() method'
    pub fn export_timestamps(&self) -> Vec<i128> {
        self.entries.iter().map(|entry|{entry.timestamp}).collect()
    }
    /// clones and collects into a new ledger any entries that the other ledger doesn't have
    /// it checks for missing entries by finding any entry in its ledger whose timestamp doesn't figure in the other's
    /// returns an empty ledger if none are missing
    pub fn fetch_missing(&self, other: &[i128]) -> Self {
        let missing_entries: Vec<LedgerEntry> = self.entries.iter().filter(|entry| {!other.contains(&entry.timestamp)}).map(|entry| {entry.clone()}).collect();
        Self { entries: missing_entries }
    }
    pub fn get_last_entry_by_type(&self, data_type: &LedgerData) -> Option<&LedgerEntry> {
        self.entries.iter().rev().find(|ledger_entry| {
            if let Data::Decrypted { data: entry_data } = &ledger_entry.data {
                match (entry_data, data_type) {
                    (LedgerData::ClipboardCopy(_), LedgerData::ClipboardCopy(_)) => true,
                    (LedgerData::EncryptionFailed, LedgerData::EncryptionFailed) => true,
                    (LedgerData::DecryptionFailed, LedgerData::DecryptionFailed) => true,
                    _ => false,
                }
            } else {false}
        })
    }
    pub fn get_last_entry_by_type_alt(&self, data_type: &LedgerData) -> Option<(&i128, &LedgerData)> {
        let last = self.get_last_entry_by_type(data_type)?;
        if let Data::Decrypted { data } = &last.data {
            Some((&last.timestamp, data))
        } else {None}
    }
    // TODO : add a method to chronologically order entries
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub timestamp: i128,
    pub data: Data,
}

impl LedgerEntry {
    pub fn new(timestamp: i128, data: Data) -> Self {
        Self { timestamp, data }
    }
    pub fn new_with_current_time(data: Data) -> Self {
        Self { timestamp: OffsetDateTime::now_utc().unix_timestamp_nanos(), data }
    }
    pub fn encrypt(&self, cipher: &XChaCha12Poly1305) -> Self {
        Self { timestamp: self.timestamp.clone(), data: self.data.encrypt(cipher) }
    }
    pub fn decrypt(&self, cipher: &XChaCha12Poly1305) -> Self {
        Self { timestamp: self.timestamp.clone(), data: self.data.decrypt(cipher) }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Data {
    Encrypted {data: Vec<u8>, nonce: Vec<u8>},
    Decrypted {data: LedgerData},
}

impl Data {
    pub fn new_encrypted(data: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self::Encrypted { data, nonce }
    }
    pub fn new_decrypted(data: LedgerData) -> Self {
        Self::Decrypted { data }
    }
    /// if successful returns an encrypted clone of itself using XChaCha12Poly1305
    /// if it fails returns an empty Encrypted {} variant
    pub fn encrypt(&self, cipher: &XChaCha12Poly1305) -> Self {
        match &self {
            Data::Encrypted { .. } => {
                self.clone()
            },
            Data::Decrypted { data } => {
                let nonce = XChaCha12Poly1305::generate_nonce(&mut OsRng);
                if let Ok(data) = bincode::serialize(data) {
                    if let Ok(cipherdata) = cipher.encrypt(&nonce, bincode::serialize(&data).unwrap_or(Vec::with_capacity(0)).as_ref()) {
                        return Data::Encrypted { data: cipherdata, nonce: nonce.to_vec() };
                    }
                }
                // generic return if the encryption fails
                Data::Encrypted { data: Vec::with_capacity(0), nonce: Vec::with_capacity(0) }
            },
        }
    }
    /// if successful returns a decrypted clone of itself using XChaCha12Poly1305
    /// if it fails returns a Decrypted { DecryptionFailed } variant
    pub fn decrypt(&self, cipher: &XChaCha12Poly1305) -> Self {
        match self {
            Data::Encrypted { data, nonce } => {
                if data.is_empty() && nonce.is_empty() {
                    return Data::Decrypted { data: LedgerData::EncryptionFailed }
                }
                if let Ok(decrypted_data) = cipher.decrypt(XNonce::from_slice(nonce), data.as_ref()) {
                    let mut size: [u8; 8] = [0; 8];
                    size.copy_from_slice(&decrypted_data[..8]);
                    let size: usize = usize::from_le_bytes(size);
                    if let Ok(ledger_data) = bincode::deserialize(&decrypted_data[8..size+8]) {
                        return Data::Decrypted { data: ledger_data };
                    }
                }
                Data::Decrypted { data: LedgerData::DecryptionFailed }
            },
            Data::Decrypted { .. } => {
                self.clone()
            },
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum LedgerData {
    ClipboardCopy(String),
    EncryptionFailed,
    DecryptionFailed,
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{KeyInit, aead::generic_array::typenum::Le};
    use super::*;
    fn get_ledger() -> Ledger {
        Ledger { entries: vec![
            LedgerEntry::new(0, Data::new_decrypted(LedgerData::ClipboardCopy("ClipboardCopy #1".to_string()))),
            LedgerEntry::new_with_current_time(Data::new_decrypted(LedgerData::ClipboardCopy("ClipboardCopy #2".to_string()))),
            LedgerEntry::new_with_current_time(Data::new_decrypted(LedgerData::EncryptionFailed)),
            LedgerEntry::new_with_current_time(Data::new_decrypted(LedgerData::DecryptionFailed)),
            LedgerEntry::new_with_current_time(Data::new_decrypted(LedgerData::ClipboardCopy("ClipboardCopy #3".to_string()))),
        ] }
    }

    #[test]
    fn ledger_cryptography() {
        let ledger: Ledger = get_ledger();
        let key = XChaCha12Poly1305::generate_key(&mut OsRng);
        let cipher = XChaCha12Poly1305::new(&key);
        let other_ledger = ledger.encrypt(&cipher).decrypt(&cipher);
        assert_eq!(ledger, other_ledger)
    }
    #[test]
    fn ledger_utility_1() {
        let ledger: Ledger = get_ledger();
        assert_eq!(ledger.entries.len(), ledger.export_timestamps().len())
    }
    #[test]
    fn ledger_utility_2_1() {
        let ledger: Ledger = get_ledger();
        assert!(ledger.fetch_missing(&ledger.export_timestamps()).is_empty())
    }
    #[test]
    fn ledger_utility_2_2() {
        let ledger: Ledger = get_ledger();
        let mut other_ledger: Ledger = ledger.clone();
        other_ledger.push_back(LedgerEntry::new(1, Data::new_decrypted(LedgerData::EncryptionFailed)));
        other_ledger.push_back(LedgerEntry::new(2, Data::new_decrypted(LedgerData::EncryptionFailed)));
        assert_eq!(other_ledger.fetch_missing(&ledger.export_timestamps()).len(), 2)
    }
    #[test]
    fn ledger_utility_3_1() {
        let ledger: Ledger = get_ledger();
        assert_eq!(ledger.entries[4], ledger.get_last_entry_by_type(&LedgerData::ClipboardCopy(String::new())).unwrap().clone())
    }
}