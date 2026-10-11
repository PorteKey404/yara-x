use std::error::Error;
use std::ffi::{CStr, OsStr, c_char};
use std::mem::ManuallyDrop;
use std::os::unix::ffi::OsStrExt;

use yara_x::errors::SerializationError;

use crate::{_yrx_set_last_error, YRX_BUFFER, YRX_RESULT, YRX_RULES};

/// Serializes the rules and their native code as an AOT file.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yrx_rules_serialize_aot(
    rules: *const YRX_RULES,
    buf: &mut *mut YRX_BUFFER,
) -> YRX_RESULT {
    let Some(rules) = (unsafe { rules.as_ref() }) else {
        return YRX_RESULT::YRX_INVALID_ARGUMENT;
    };
    match rules.inner().serialize_aot() {
        Ok(bytes) => {
            let mut bytes = ManuallyDrop::new(bytes.into_boxed_slice());
            *buf = Box::into_raw(Box::new(YRX_BUFFER {
                data: bytes.as_mut_ptr(),
                length: bytes.len(),
            }));
            _yrx_set_last_error::<SerializationError>(None);
            YRX_RESULT::YRX_SUCCESS
        }
        Err(err) => {
            _yrx_set_last_error(Some(err));
            YRX_RESULT::YRX_SERIALIZATION_ERROR
        }
    }
}

/// Loads an AOT file without compiling anything. The file must be trusted
/// and must not change while the rules are alive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn yrx_rules_deserialize_aot_file(
    path: *const c_char,
    rules: &mut *mut YRX_RULES,
) -> YRX_RESULT {
    if path.is_null() {
        return YRX_RESULT::YRX_INVALID_ARGUMENT;
    }
    let path = OsStr::from_bytes(unsafe { CStr::from_ptr(path) }.to_bytes());
    match yara_x::Rules::deserialize_aot_file(path) {
        Ok(r) => {
            *rules = Box::into_raw(YRX_RULES::boxed(r));
            _yrx_set_last_error::<SerializationError>(None);
            YRX_RESULT::YRX_SUCCESS
        }
        Err(err) => {
            // Message avec ses causes
            let mut msg = err.to_string();
            let mut src = err.source();
            while let Some(e) = src {
                msg = format!("{msg}: {e}");
                src = e.source();
            }
            _yrx_set_last_error(Some(msg));
            YRX_RESULT::YRX_SERIALIZATION_ERROR
        }
    }
}

#[cfg(test)]
mod tests;
