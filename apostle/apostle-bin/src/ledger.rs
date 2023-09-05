use serde::{Serialize, Deserialize};
use bincode;

pub struct Ledger {
    entries: Vec<LedgerEntry>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    timestamp: u64,
    data_type: DataType,
    data: Vec<u8>,
    nonce: Option<Vec<u8>>,
}

impl LedgerEntry {

}

#[derive(Debug, Serialize, Deserialize)]
pub enum DataType {
    ClipboardCopy,
}