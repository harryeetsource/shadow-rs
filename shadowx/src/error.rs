use alloc::string::String;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ShadowError {
    /// Represents an error where an API call failed.
    ///
    /// * `{0}` - The name of the API.
    /// * `{1}` - The status code returned by the API.
    #[error("{0} Failed With Status: {1}")]
    ApiCallFailed(&'static str, i32),

    /// Represents an error where a function execution failed at a specific line.
    ///
    /// * `{0}` - The name of the function.
    /// * `{1}` - The line number where the function failed.
    #[error("{0} function failed on the line: {1}")]
    FunctionExecutionFailed(&'static str, u32),

    /// Represents an error when an invalid memory access occurs.
    #[error("Invalid memory access at address")]
    InvalidMemory,

    /// Error when a process with a specific identifier is not found.
    ///
    /// This error is returned when the system cannot locate a process with the given
    /// identifier (e.g., PID or process name).
    ///
    /// * `{0}` - The identifier of the process that was not found.
    #[error("Process with identifier {0} not found")]
    ProcessNotFound(String),

    /// Error when a thread with a specific TID is not found.
    ///
    /// This error occurs when a thread with the specified TID cannot be located in the system.
    ///
    /// * `{0}` - The thread identifier (TID) that was not found.
    #[error("Thread with TID {0} not found")]
    ThreadNotFound(usize),

    /// Represents an invalid device request error.
    ///
    /// This error occurs when an invalid or unsupported request is made to a device.
    #[error("Invalid Device Request")]
    InvalidDeviceRequest,

    /// Represents an error where a null pointer was encountered.
    ///
    /// This error occurs when a null pointer is encountered during an operation that
    /// requires a valid memory reference.
    ///
    /// * `{0}` - The name of the pointer that was null.
    #[error("Pointer is null: {0}")]
    NullPointer(&'static str),

    /// Represents an error where a string conversion from a raw pointer failed.
    ///
    /// This error is returned when the system fails to convert a raw pointer to a string,
    /// typically during Unicode or ANSI string conversions.
    ///
    /// * `{0}` - The memory address of the raw pointer that failed to convert.
    #[error("Failed to convert string from raw pointer at {0}")]
    StringConversionFailed(usize),

    /// Represents an error where a specific module was not found.
    ///
    /// This error occurs when a module (e.g., a DLL or driver) with the specified name
    /// cannot be found in the system.
    ///
    /// * `{0}` - The name of the module that was not found.
    #[error("Module {0} not found")]
    ModuleNotFound(String),

    /// Represents an error where a driver with a specific name was not found.
    ///
    /// This error occurs when a driver with the given name cannot be found in the
    /// system's loaded drivers list.
    ///
    /// * `{0}` - The name of the driver that was not found.
    #[error("Driver {0} not found")]
    DriverNotFound(String),

    /// Represents an error where a pattern scan failed to locate a required pattern in memory.
    ///
    /// This error occurs when a memory pattern scan fails to match the expected byte sequence.
    #[error("Pattern not found")]
    PatternNotFound,

    /// Represents an error where a function could not be found in the specified module.
    ///
    /// This error occurs when a named function is not found in a given module (DLL).
    ///
    /// * `{0}` - The name of the function that was not found.
    #[error("Function {0} not found in module")]
    FunctionNotFound(String),

    /// Represents an unknown failure in the system.
    ///
    /// This is a generic catch-all error for unexpected failures. It includes the name of
    /// the failing operation and the line number where the failure occurred.
    ///
    /// * `{0}` - The operation that failed.
    /// * `{1}` - The line number where the failure occurred.
    #[error("Unknown failure in {0}, at line {1}")]
    UnknownFailure(&'static str, u32),

    /// Represents an error when installing or uninstalling a hook on the Nsiproxy driver.
    ///
    /// This error occurs when the system fails to install or remove a hook on the Nsiproxy driver.
    #[error("Error handling hook on Nsiproxy driver")]
    HookFailure,

    /// Represents an error when a buffer is too small to complete an operation.
    ///
    /// This error occurs when the provided buffer is not large enough to hold the expected
    /// data, resulting in an operation failure.
    #[error("Small buffer")]
    BufferTooSmall,

    /// Represents an error when a buffer is misaligned for the expected data structure.
    ///
    /// This error occurs when the provided buffer does not have the correct memory alignment
    /// required for safe access.
    #[error("Misaligned buffer")]
    MisalignedBuffer,

    /// Error indicating that a callback could not be found.
    ///
    /// This occurs when the system is unable to locate the expected callback function.
    #[error("Error searching for the callback")]
    CallbackNotFound,

    /// Error indicating that a target with a specific index was not found.
    ///
    /// This occurs when an operation fails to locate an item by its index in a list or array.
    ///
    /// # Fields
    ///
    /// * `{0}` - The index of the target that was not found.
    #[error("Target not found with index: {0}")]
    IndexNotFound(usize),

    /// Error indicating that a failure occurred while removing a callback.
    ///
    /// This occurs when the system fails to remove a callback that was previously registered.
    #[error("Error removing a callback")]
    RemoveFailureCallback,
    /// Represents an error when the process's active list entry is invalid,
    /// such as when both the forward and backward pointers are null.
    #[error("Invalid list entry encountered")]
    InvalidListEntry,

    /// Error indicating that a failure occurred while restoring a callback.
    ///
    /// This occurs when the system fails to restore a previously removed callback.
    #[error("Error restoring a callback")]
    RestoringFailureCallback,
}
impl ShadowError {
    pub fn to_ntstatus(&self) -> i32 {
        match *self {
            ShadowError::ApiCallFailed(_, status) => status as i32,
            ShadowError::FunctionExecutionFailed(_, _) => 0xC0000001u32 as i32, // STATUS_UNSUCCESSFUL
            ShadowError::InvalidMemory => 0xC0000005u32 as i32, // STATUS_ACCESS_VIOLATION
            ShadowError::ProcessNotFound(_) => 0xC0000225u32 as i32, // STATUS_NOT_FOUND (example)
            ShadowError::ThreadNotFound(_) => 0xC0000120u32 as i32, // Example code for thread not found
            ShadowError::InvalidDeviceRequest => 0xC0000022u32 as i32, // STATUS_INVALID_DEVICE_REQUEST
            ShadowError::NullPointer(_) => 0xC0000008u32 as i32, // STATUS_INVALID_HANDLE
            ShadowError::StringConversionFailed(_) => 0xC0000023u32 as i32, // STATUS_BUFFER_TOO_SMALL
            ShadowError::ModuleNotFound(_) => 0xC0000135u32 as i32, // STATUS_DLL_NOT_FOUND
            ShadowError::DriverNotFound(_) => 0xC000012Fu32 as i32, // STATUS_DRIVER_ENTRYPOINT_NOT_FOUND (example)
            ShadowError::PatternNotFound => 0xC0000225u32 as i32, // STATUS_NOT_FOUND
            ShadowError::FunctionNotFound(_) => 0xC0000142u32 as i32, // STATUS_DLL_INIT_FAILED (example)
            ShadowError::UnknownFailure(_, _) => 0xC0000001u32 as i32, // STATUS_UNSUCCESSFUL
            ShadowError::HookFailure => 0xC0000100u32 as i32, // Example error code for hook failure
            ShadowError::BufferTooSmall => 0xC0000023u32 as i32, // STATUS_BUFFER_TOO_SMALL
            ShadowError::MisalignedBuffer => 0xC0000090u32 as i32, // STATUS_DATATYPE_MISALIGNMENT
            ShadowError::CallbackNotFound => 0xC0000123u32 as i32, // Example error code for callback not found
            ShadowError::IndexNotFound(_) => 0xC0000225u32 as i32, // STATUS_NOT_FOUND
            ShadowError::RemoveFailureCallback => 0xC0000120u32 as i32, // Example code
            ShadowError::InvalidListEntry => 0xC0000001u32 as i32, // STATUS_UNSUCCESSFUL
            ShadowError::RestoringFailureCallback => 0xC0000120u32 as i32, // Example code
        }
    }
}
