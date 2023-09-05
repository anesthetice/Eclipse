use windows::Win32::{
    System::{
        DataExchange::{OpenClipboard, GetClipboardOwner, GetClipboardData, CloseClipboard},
        Memory::GlobalSize,
    },
    Foundation::HGLOBAL,
};

/// get_clipboard attempts to collect the clipboard's content to a string
/// returns None instead of a proper error since I don't see the point in handling a windows-related error
pub fn get_clipboard() -> Option<String> {
    unsafe {
        use std::os::raw::c_void;
        OpenClipboard(GetClipboardOwner()).ok()?;
        // CF_TEXT = 1
        // not using GlobalLock as we are not writing anything
        let clipboard_data: *mut c_void = GetClipboardData(1).ok()?.0 as *mut c_void;
        let size: usize = GlobalSize(HGLOBAL(clipboard_data));
        let ptr: *const u8 = clipboard_data as *const u8;
        let string: String = String::from_utf8_lossy(std::slice::from_raw_parts(ptr, size)).to_string();
        let _ = CloseClipboard();
        Some(string.to_string())
    }
}