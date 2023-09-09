use serde::{Serialize, Deserialize};
use bincode;
use chacha20poly1305::{
    aead::{Aead, AeadCore, OsRng},
    XChaCha12Poly1305, XNonce
};

#[derive(Debug, PartialEq)]
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
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub timestamp: u64,
    pub data: Data,
}

impl LedgerEntry {
    pub fn new(timestamp: u64, data: Data) -> Self {
        Self { timestamp, data }
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
    use chacha20poly1305::KeyInit;
    use super::*;
    #[test]
    fn encrypt_decrypt_ledger() {
        let ledger: Ledger = Ledger { entries: vec![
            LedgerEntry::new(124, Data::new_decrypted(LedgerData::ClipboardCopy("clipboard copy test #1".to_string())))
        ] };
        let key = XChaCha12Poly1305::generate_key(&mut OsRng);
        let cipher = XChaCha12Poly1305::new(&key);
        let other_ledger = ledger.encrypt(&cipher).decrypt(&cipher);
        assert_eq!(ledger, other_ledger)
    }
}