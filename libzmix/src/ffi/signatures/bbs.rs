use super::super::ByteArray;
use signatures::bbs::prelude::{SecretKey, PublicKey, Signature};
use signatures::prelude::{SignatureMessage};
use std::ffi::{CStr,CString};
use ffi_support::{ByteBuffer, ErrorCode, ExternError, FfiStr};
use std::os::raw::{c_char, c_void};

use serde_json;
use signatures::bbs::keys::KeyGenOptions;

use amcl_wrapper::{
    constants::{FieldElement_SIZE, GroupG1_SIZE}, errors::SerzDeserzError, field_elem::FieldElement,
    group_elem::GroupElement, group_elem_g1::G1, group_elem_g2::G2, types_g2::GroupG2_SIZE,
};

pub mod bbs_error_codes {
    pub const SIGNING_ERROR: i32 = 1;
    pub const VERIFYING_ERROR: i32 = 2;
    pub const KEYGEN_ERROR: i32 = 3;
}

#[no_mangle]
pub extern "C" fn zmix_bbs_generate(private_key: &mut ByteBuffer,
                                    public_key: &mut ByteBuffer,
                                    err: &mut ExternError) -> i32 {
    match PublicKey::generate_key() {
        Ok((publicKey, privateKey)) => {
            *private_key = ByteBuffer::from(privateKey.to_bytes());
            *public_key = ByteBuffer::from(publicKey.w.to_bytes());
            1
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(bbs_error_codes::KEYGEN_ERROR),
                e.to_string(),
            );
            0
        }
    }
}

/// Sign a message with BBS.
#[no_mangle]
pub extern "C" fn zmix_bbs_sign(
    messages_json: FfiStr,
    private_key: &ByteArray,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let messages = serde_json::from_str::<Vec<String>>(messages_json.as_str()).unwrap();
    let secretKey = SecretKey::from_bytes(private_key.to_vec().as_slice()).unwrap();
    let publicKey = PublicKey::generate_from_count(messages.len(), KeyGenOptions::FromSecretKey(secretKey.clone())).unwrap();

    let mut message_hashes = Vec::new();
    for message in messages {
        let msg_hash = FieldElement::from_msg_hash(message.as_bytes());
        message_hashes.push(msg_hash);
    }

    match Signature::new(
        &message_hashes,
        &secretKey.clone(),
        &publicKey
    )  {
        Ok(sig) => {
            *err = ExternError::success();
            *signature = ByteBuffer::from_vec(sig.to_bytes());
            1
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(bbs_error_codes::SIGNING_ERROR),
                e.to_string(),
            );
            0
        }
    }
}

/// Verify a message with BBS.
#[no_mangle]
pub extern "C" fn zmix_bbs_verify(
    messages_json: FfiStr,
    public_key: &ByteArray,
    signature: &ByteArray,
    err: &mut ExternError,
) -> i32 {
    let messages = serde_json::from_str::<Vec<String>>(messages_json.as_str()).unwrap();
    let publicKey = PublicKey::generate_from_count(messages.len(), KeyGenOptions::FromRawCommitment(public_key.to_vec())).unwrap();

    let mut message_hashes = Vec::new();
    for message in messages {
        let msg_hash = FieldElement::from_msg_hash(message.as_bytes());
        message_hashes.push(msg_hash);
    }

    let sig = Signature::from_bytes(signature.to_vec().as_slice()).unwrap();

    match sig.verify(&message_hashes, &publicKey)
    {
        Ok(verified) => {
            *err = ExternError::success();
            if (verified) {
                return 1;
            }
            0
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(bbs_error_codes::SIGNING_ERROR),
                e.to_string(),
            );
            0
        }
    }
}