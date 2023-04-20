use lazy_static::{
    lazy_static,
    initialize as ls_initialize,
};
use sled;
use tokio;

mod database;

lazy_static! {
    pub static ref BEHELIT_DB : sled::Db = sled::open("behelitDB").unwrap();
}


#[tokio::main]
async fn main() {
    ls_initialize(&BEHELIT_DB);
}
