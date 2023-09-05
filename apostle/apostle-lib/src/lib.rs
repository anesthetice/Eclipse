use dll_syringe::{Syringe, process::OwnedProcess};
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};


#[no_mangle]
#[allow(non_snake_case, unused_variables)]
extern "system" fn DllMain(
    dll_module: HINSTANCE,
    call_reason: u32,
    _: *mut ())
    -> bool
{
    match call_reason {
        DLL_PROCESS_ATTACH => {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open("C:\\Warehouse\\apostle.log").unwrap();
            writeln!(&mut file, "DLL_PROCESS_ATTACH : {:?}", dll_module).unwrap();
            std::thread::spawn(move || { loop {
                writeln!(&mut file, "RUNNING").unwrap();
                std::thread::sleep(std::time::Duration::from_secs(1));
            }});
        },
        DLL_PROCESS_DETACH => {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new().append(true).open("C:\\Warehouse\\apostle.log").unwrap();
            writeln!(&mut file, "DLL_PROCESS_DETACH : {:?}", dll_module).unwrap();

            let target_process = match OwnedProcess::find_first_by_name("Notepad") {
                Some(data) => data,
                None => {
                    writeln!(&mut file, "uhoh1").unwrap();
                    panic!("");
                }
            };
            let syringe = Syringe::for_process(target_process);
            match syringe.inject("D:/Rust/Eclipse/apostle/apostle-bin/apostle_lib.dll") {
                Ok(a) => (),
                Err(error) => writeln!(&mut file, "uhoh2 : {:?}", error).expect("a"),
            };
        },
        _=> (),    
    }
    true
}

#[no_mangle]
pub extern "C" fn execute() {
    ();
}
#[no_mangle]
pub extern "C" fn run() {
    ();
}