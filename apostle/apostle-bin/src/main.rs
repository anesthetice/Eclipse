use chacha20poly1305::{XChaCha12Poly1305, KeyInit};
use dll_syringe::{Syringe, process::OwnedProcess};

mod utils;
use utils::*;

mod ledger;
use ledger::*;

mod config;
use config::*;

#[tokio::main]
async fn main() {
    /*
    let target_process = OwnedProcess::find_first_by_name("mspaint").unwrap();
    let syringe = Syringe::for_process(target_process);
    let injected_payload = syringe.inject("apostle_lib.dll").unwrap();
    */
}

