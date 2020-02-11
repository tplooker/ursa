use super::super::ByteArray;
use signatures::bbs::prelude::{SecretKey, PublicKey, Signature};
use signatures::prelude::{SignatureMessage};

use ffi_support::{ByteBuffer, ErrorCode, ExternError};

pub mod bbs_error_codes {
    pub const SIGNING_ERROR: i32 = 1;
    pub const VERIFYING_ERROR: i32 = 2;
}

/// Sign a message with BBS.
#[no_mangle]
pub extern "C" fn zmix_bbs_sign(
    messages: &ByteArray,
    sign_key: &ByteArray,
    ver_key: &ByteArray,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let signKey = SecretKey::from_bytes(sign_key.to_vec().as_slice()).unwrap();
    let verKey = PublicKey::from_bytes(ver_key.to_vec().as_slice()).unwrap();
    let msgs = SignatureMessage::from_bytes(messages.to_vec().as_slice()).unwrap();

    match Signature::new(
        &msgs,
        &signKey,
        &verKey
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
    messages: &ByteArray,
    ver_key: &ByteArray,
    signature: &mut ByteBuffer,
    err: &mut ExternError,
) -> i32 {
    let signKey = SecretKey::from_bytes(sign_key.to_vec().as_slice()).unwrap();
    let verKey = PublicKey::from_bytes(ver_key.to_vec().as_slice()).unwrap();
    let msgs = SignatureMessage::from_bytes(messages.to_vec().as_slice()).unwrap();

    match Signature::new(
        msgs,
        &signKey,
        &verKey
    )  {
        Ok(sig) => {
            *err = ExternError::success();
            *signature = ByteBuffer::from_vec(sig.to_bytes());
            1
        }
        Err(e) => {
            *err = ExternError::new_error(
                ErrorCode::new(bbs_error_codes::VERIFYING_ERROR),
                e.to_string(),
            );
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_bbs_sign() {
        let mut public_key = ByteBuffer::new_with_size(ursa_ed25519_get_public_key_size() as usize);
        let mut private_key =
            ByteBuffer::new_with_size(ursa_ed25519_get_private_key_size() as usize);
        let mut error = ExternError::success();
        let seed = vec![1u8; 32];
        let seed_wrapper = ByteArray::from(&seed);
        let res = ursa_ed25519_keypair_from_seed(
            &seed_wrapper,
            &mut public_key,
            &mut private_key,
            &mut error,
        );
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
        let pk = public_key.into_vec();
        let sk = private_key.into_vec();

        let mut signature = ByteBuffer::new_with_size(ursa_ed25519_get_signature_size() as usize);
        let message = b"Wepa! This is a message that should be signed.";
        let message_wrapper = ByteArray::from(&message[..]);
        let sk_wrapper = ByteArray::from(&sk);

        let res = ursa_ed25519_sign(&message_wrapper, &sk_wrapper, &mut signature, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());

        let sig = signature.into_vec();
        let sig_wrapper = ByteArray::from(&sig);
        let pk_wrapper = ByteArray::from(&pk);
        assert_eq!("f61dc466c3094522987cf9bdbadf8a455bc9401d0e56e1a7696483de85c646216648eb9f7f8003822d4c8702016ffe3b4a218ed776776ae5b53d5394bbadb509".to_string(), hex::encode(sig.as_slice()));
        let res = ursa_ed25519_verify(&message_wrapper, &sig_wrapper, &pk_wrapper, &mut error);
        assert_eq!(res, 1);
        assert!(error.get_code().is_success());
    }
}