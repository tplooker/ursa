use amcl_wrapper::{
    constants::{FieldElement_SIZE, GroupG1_SIZE}, errors::SerzDeserzError, field_elem::FieldElement,
    group_elem::GroupElement, group_elem_g1::G1, group_elem_g2::G2, types_g2::GroupG2_SIZE,
};

use ursa::hash::{Input, VariableOutput, blake2::VarBlake2};

use crate::errors::prelude::*;

pub mod prelude {
    pub use super::{generate, PublicKey, SecretKey};
}

// https://eprint.iacr.org/2016/663.pdf Section 4.3
pub type SecretKey = FieldElement;

/// `PublicKey` consists of a blinding generator `h0`, a commitment to the secret key `w`
/// and a generator for each message in `h`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PublicKey {
    pub h0: G1,     //blinding factor base
    pub h: Vec<G1>, //base for each message to be signed
    pub w: G2,      //commitment to private key
}

impl PublicKey {
    pub fn message_count(&self) -> usize {
        self.h.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(GroupG1_SIZE * (self.h.len() + 1) + 4 + GroupG2_SIZE);
        out.extend_from_slice(self.w.to_bytes().as_slice());
        out.extend_from_slice(self.h0.to_bytes().as_slice());
        out.extend_from_slice(&(self.h.len() as u32).to_be_bytes());
        for p in &self.h {
            out.extend_from_slice(p.to_bytes().as_slice());
        }
        out
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, SerzDeserzError> {
        let mut index = 0;
        let w = G2::from_bytes(&data[0..GroupG2_SIZE])?;
        index += GroupG2_SIZE;
        let h0 = G1::from_bytes(&data[index..(index + GroupG1_SIZE)])?;
        index += GroupG1_SIZE;
        let h_size = u32::from_be_bytes([
            data[index],
            data[index + 1],
            data[index + 2],
            data[index + 3],
        ]) as usize;
        let mut h = Vec::with_capacity(h_size);
        index += 4;
        for _ in 0..h_size {
            let p = G1::from_bytes(&data[index..(index + GroupG1_SIZE)])?;
            h.push(p);
            index += GroupG1_SIZE;
        }
        Ok(PublicKey { w, h0, h })
    }

    // Make sure no generator is identity
    pub fn validate(&self) -> Result<(), BBSError> {
        if self.h0.is_identity() || self.w.is_identity() || self.h.iter().any(|v| v.is_identity()) {
            Err(BBSError::from_kind(BBSErrorKind::MalformedPublicKey))
        } else {
            Ok(())
        }
    }

    pub fn generate(attributes: &[&str], option: KeyGenOptions) -> Result<Self, BBSError> {
        match option {
            KeyGenOptions::FromCommitment(w) => generate_public_key_from_commitment(attributes, &w),
            KeyGenOptions::FromRawCommitment(rawCommitment) => {
                let w = G2::from_bytes(rawCommitment.as_slice()).unwrap();
                generate_public_key_from_commitment(attributes, &w)
            },
            KeyGenOptions::FromSecretKey(s) => generate_public_key_from_private_key(attributes, &s)
        }
    }

    pub fn generate_from_count(message_count: usize, option: KeyGenOptions) -> Result<Self, BBSError> {
        match option {
            KeyGenOptions::FromCommitment(w) => generate_public_key_from_commitment_and_no_of_messages(message_count, &w),
            KeyGenOptions::FromRawCommitment(rawCommitment) => {
                let w = G2::from_bytes(rawCommitment.as_slice()).unwrap();
                generate_public_key_from_commitment_and_no_of_messages(message_count, &w)
            },
            KeyGenOptions::FromSecretKey(s) => generate_public_key_from_private_key_and_no_of_messages(message_count, &s)
        }
    }

    pub fn generate_key() -> Result<(Self, SecretKey), BBSError> {
        return generate_key();
    }
}

#[derive(Debug)]
pub enum KeyGenOptions {
    FromSecretKey(SecretKey),
    FromCommitment(G2),
    FromRawCommitment(Vec<u8>),
}

/// Used to generate the public key when the private key is unknown
fn generate_public_key_from_commitment(attributes: &[&str], w: &G2) -> Result<PublicKey, BBSError> {
    let mut hasher = VarBlake2::new(FieldElement_SIZE).unwrap();

    hasher.input(w.to_bytes().as_slice());
    let mut h = Vec::new();
    for a in attributes {
        let f_h = FieldElement::from_msg_hash(a.as_bytes());
        let h_i = G1::generator().scalar_mul_const_time(&f_h);
        hasher.input(h_i.to_bytes().as_slice());
        h.push(h_i);
    }
    let mut hash = [0u8; FieldElement_SIZE];
    hasher.variable_result(|res| {
        hash.copy_from_slice(res);
    });
    let h0 = G1::generator().scalar_mul_const_time(&FieldElement::from_msg_hash(&hash[..]));

    Ok(
        PublicKey {
            w: w.clone(),
            h0,
            h,
        },
    )
}

/// Generate the public key when only the private key is known
fn generate_public_key_from_private_key(attributes: &[&str], secret: &FieldElement) -> Result<PublicKey, BBSError> {
    let w = &G2::generator() * secret;
    generate_public_key_from_commitment(attributes, &w)
}

fn generate_public_key_from_commitment_and_no_of_messages(message_count: usize, w: &G2) -> Result<PublicKey, BBSError> {
    //Derive h0 = HASH(pubKey + 1);
    const h0_index: u8 = 1;
    let mut hasher = VarBlake2::new(FieldElement_SIZE).unwrap();
    hasher.input(w.to_bytes().as_slice());
    hasher.input(h0_index.to_be_bytes());
    let mut h0hash = [0u8; FieldElement_SIZE];
    hasher.variable_result(|res| {
        h0hash.copy_from_slice(res);
    });
    let h0 = G1::generator().scalar_mul_const_time(&FieldElement::from_msg_hash(&h0hash[..]));

    //Derive h_0..h_i where i == message_count
    let mut h = Vec::new();
    for i in 2..message_count+2 {
        let mut attribute_hasher = VarBlake2::new(FieldElement_SIZE).unwrap();
        attribute_hasher.input(w.to_bytes().as_slice());
        attribute_hasher.input(i.to_be_bytes());
        let mut attribute_hash = [0u8; FieldElement_SIZE];
        attribute_hasher.variable_result(|res| {
            attribute_hash.copy_from_slice(res);
        });
        let f_h = FieldElement::from_msg_hash(&attribute_hash[..]);
        h.push(G1::generator().scalar_mul_const_time(&f_h));
    }

    Ok(
        PublicKey {
            w: w.clone(),
            h0,
            h,
        },
    )
}

fn generate_public_key_from_private_key_and_no_of_messages(message_count: usize, secret: &FieldElement) -> Result<PublicKey, BBSError> {
    if message_count == 0 {
        return Err(BBSError::from_kind(BBSErrorKind::KeyGenError));
    }

    //create public key
    let w = &G2::generator() * secret;

    generate_public_key_from_commitment_and_no_of_messages(message_count, &w)
}

/// Create a new BBS+ keypair
pub fn generate_key() -> Result<(PublicKey, SecretKey), BBSError> {
    let secret = FieldElement::random();

    // Super paranoid could allow a context to generate the generator from a well known value
    // Not doing this for now since any generator in a prime field should be okay.
    let w = &G2::generator() * &secret;
    Ok((
        PublicKey {
            w,
            h0: G1::random(), //TODO need to discuss
            h: [G1::random()].to_vec()  //TODO need to discuss
        },
        secret,
    ))
}

/// Create a new BBS+ keypair
pub fn generate(message_count: usize) -> Result<(PublicKey, SecretKey), BBSError> {
    if message_count == 0 {
        return Err(BBSError::from_kind(BBSErrorKind::KeyGenError));
    }
    let secret = FieldElement::random();

    // Super paranoid could allow a context to generate the generator from a well known value
    // Not doing this for now since any generator in a prime field should be okay.
    let w = &G2::generator() * &secret;
    let mut h = Vec::new();
    for _ in 0..message_count {
        h.push(G1::random());
    }
    Ok((
        PublicKey {
            w,
            h0: G1::random(),
            h,
        },
        secret,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_generate() {
        let res = generate_key();
        assert!(res.is_err());
        //Check to make sure key has correct size
        let (public_key, _) = generate(1).unwrap();
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GroupG1_SIZE * 2 + 4 + GroupG2_SIZE);

        let (public_key, _) = generate(5).unwrap();
        assert_eq!(public_key.message_count(), 5);
        //Check key doesn't contain any invalid points
        assert!(public_key.validate().is_ok());
        let bytes = public_key.to_bytes();
        assert_eq!(bytes.len(), GroupG1_SIZE * 6 + 4 + GroupG2_SIZE);
        //Check serialization is working
        let public_key_2 = PublicKey::from_bytes(bytes.as_slice()).unwrap();
        assert_eq!(public_key_2, public_key);
    }

    #[test]
    fn determistic_generate() {
        let mut attributes = Vec::new();
        attributes.push("first_name");
        attributes.push("last_name");
        attributes.push("date_of_birth");
        attributes.push("gender");

        let secret = SecretKey::random();

        let res = generate_public_key_from_private_key(attributes.as_slice(), &secret);
        assert!(res.is_ok());
        let pk = res.unwrap();

        let res = generate_public_key_from_private_key(attributes.as_slice(), &secret);
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);

        let w = &G2::generator() * &secret;

        let res = generate_public_key_from_commitment(attributes.as_slice(), &w);
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);

        let res = PublicKey::generate(attributes.as_slice(), KeyGenOptions::FromSecretKey(secret));
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);

        let res = PublicKey::generate(attributes.as_slice(), KeyGenOptions::FromCommitment(w));
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);
    }

    #[test]
    fn determistic_generate_1() {
        let secret = SecretKey::random();
        let msg_count = 10;

        let res = generate_public_key_from_private_key_and_no_of_messages(msg_count, &secret);
        assert!(res.is_ok());
        let pk = res.unwrap();

        let res = generate_public_key_from_private_key_and_no_of_messages(msg_count, &secret);
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);

        let w = &G2::generator() * &secret;

        let res = generate_public_key_from_commitment_and_no_of_messages(msg_count, &w);
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);

        let res = PublicKey::generate_from_count(msg_count, KeyGenOptions::FromSecretKey(secret));
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);

        let res = PublicKey::generate_from_count(msg_count, KeyGenOptions::FromCommitment(w));
        assert!(res.is_ok());
        let pk1 = res.unwrap();
        assert_eq!(pk, pk1);
    }
}
