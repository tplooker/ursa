
pub mod signatures;

use signatures::bbs::prelude::*;
use errors::prelude::*;
use ffi_support::ByteBuffer;
use std::os::raw::c_char;

use errors::prelude::*;
/// Used for receiving a ByteBuffer from C that was allocated by either C or Rust.
/// If Rust allocated, then the outgoing struct is ffi_support::ByteBuffer
/// Caller is responsible for calling free where applicable.
///
/// C will not notice a difference and can use the same struct
#[repr(C)]
pub struct ByteArray {
    length: usize,
    data: *const u8,
}

impl Default for ByteArray {
    fn default() -> ByteArray {
        ByteArray {
            length: 0,
            data: std::ptr::null(),
        }
    }
}

impl ByteArray {
    pub fn to_vec(&self) -> Vec<u8> {
        if self.data.is_null() || self.length == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(self.data, self.length).to_vec() }
        }
    }

    pub fn to_opt_vec(&self) -> Option<Vec<u8>> {
        if self.data.is_null() {
            None
        } else if self.length == 0 {
            Some(Vec::new())
        } else {
            Some(unsafe { std::slice::from_raw_parts(self.data, self.length).to_vec() })
        }
    }

    pub fn into_byte_buffer(self) -> ByteBuffer {
        unsafe { std::mem::transmute(self) }
    }
}

impl From<&Vec<u8>> for ByteArray {
    fn from(input: &Vec<u8>) -> ByteArray {
        ByteArray {
            length: input.len(),
            data: input.as_slice().as_ptr() as *const u8,
        }
    }
}
impl From<Vec<u8>> for ByteArray {
    fn from(input: Vec<u8>) -> ByteArray {
        let mut buf = input.into_boxed_slice();
        let data = buf.as_mut_ptr();
        let len = buf.len();
        std::mem::forget(buf);
        Self { data, length: len }
    }
}

impl From<&[u8]> for ByteArray {
    fn from(input: &[u8]) -> ByteArray {
        ByteArray {
            length: input.len(),
            data: input.as_ptr() as *const u8,
        }
    }
}

impl From<ByteBuffer> for ByteArray {
    fn from(b: ByteBuffer) -> Self {
        b.into_vec().into()
    }
}

//define_bytebuffer_destructor!(ursa_bytebuffer_free);
//define_string_destructor!(ursa_string_free);

#[derive(Debug, PartialEq, Copy, Clone)]
#[repr(usize)]
pub enum ErrorCode {
    Success = 0,

    // Common errors

    // Caller passed invalid value as param 1 (null, invalid json and etc..)
    CommonInvalidParam1 = 100,

    // Caller passed invalid value as param 2 (null, invalid json and etc..)
    CommonInvalidParam2 = 101,

    // Caller passed invalid value as param 3 (null, invalid json and etc..)
    CommonInvalidParam3 = 102,

    // Caller passed invalid value as param 4 (null, invalid json and etc..)
    CommonInvalidParam4 = 103,

    // Caller passed invalid value as param 5 (null, invalid json and etc..)
    CommonInvalidParam5 = 104,

    // Caller passed invalid value as param 6 (null, invalid json and etc..)
    CommonInvalidParam6 = 105,

    // Caller passed invalid value as param 7 (null, invalid json and etc..)
    CommonInvalidParam7 = 106,

    // Caller passed invalid value as param 8 (null, invalid json and etc..)
    CommonInvalidParam8 = 107,

    // Caller passed invalid value as param 9 (null, invalid json and etc..)
    CommonInvalidParam9 = 108,

    // Caller passed invalid value as param 10 (null, invalid json and etc..)
    CommonInvalidParam10 = 109,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam11 = 110,

    // Caller passed invalid value as param 11 (null, invalid json and etc..)
    CommonInvalidParam12 = 111,

    // Invalid library state was detected in runtime. It signals library bug
    CommonInvalidState = 112,

    // Object (json, config, key, credential and etc...) passed by library caller has invalid structure
    CommonInvalidStructure = 113,

    // IO Error
    CommonIOError = 114,

    // Trying to issue non-revocation credential with full anoncreds revocation accumulator
    AnoncredsRevocationAccumulatorIsFull = 115,

    // Invalid revocation accumulator index
    AnoncredsInvalidRevocationAccumulatorIndex = 116,

    // Credential revoked
    AnoncredsCredentialRevoked = 117,

    // Proof rejected
    AnoncredsProofRejected = 118,
}