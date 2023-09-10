use std::path::PathBuf;

pub enum ApostleModules {
    ClipboardCopy,
    Location,
    Activity,
    WebHistory,
}

pub struct ApostleConfig {
    active_modules: Vec<ApostleModules>,
    active_storage: PathBuf,
}