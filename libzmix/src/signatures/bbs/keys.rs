use amcl_wrapper::{
    constants::{FieldElement_SIZE, GroupG1_SIZE}, errors::SerzDeserzError, field_elem::FieldElement,
    group_elem::GroupElement, group_elem_g1::G1, group_elem_g2::G2, types_g2::GroupG2_SIZE,
};


use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::collections::BTreeSet;
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
}

pub struct DeterministicGenerator {
    attributes: BTreeSet<String>,
    rng: ChaChaRng
}

impl DeterministicGenerator {
    pub fn new(attributes: &BTreeSet<String>, entropy: Option<&[u8]>) -> Self {
        let mut hasher = VarBlake2::new(32).unwrap();
        // Domain separation
        hasher.input(b"bbs+ deterministric generator");
        if let Some(e) = entropy {
            hasher.input(e);
        }
        for a in attributes {
            hasher.input(a.as_bytes());
        }
        let mut seed = [0u8; 32];
        hasher.variable_result(|res| {
            seed.copy_from_slice(res);
        });
        let rng = ChaChaRng::from_seed(seed);
        Self {
            attributes: attributes.clone(),
            rng
        }
    }
}

/// Create a new BBS+ keypair using a `DeterministicGenerator`
pub fn generate_deterministically(generator: &mut DeterministicGenerator) -> Result<(PublicKey, SecretKey), BBSError> {
    let secret = SecretKey::random_using_rng(&mut generator.rng);

    let mut hasher = VarBlake2::new(FieldElement_SIZE).unwrap();
    let w = &G2::generator() * &secret;
    hasher.input(w.to_bytes().as_slice());
    let mut h = Vec::new();
    for a in &generator.attributes {
        let f_r = FieldElement::random_using_rng(&mut generator.rng);
        let mut h_i = G1::generator().scalar_mul_const_time(&f_r);

        let f_h = FieldElement::from_msg_hash(a.as_bytes());
        h_i = h_i.scalar_mul_const_time(&f_h);
        hasher.input(h_i.to_bytes().as_slice());
        h.push(h_i);
    }
    let mut hash = [0u8; FieldElement_SIZE];
    hasher.variable_result(|res| {
        hash.copy_from_slice(res);
    });
    let mut h0 = G1::generator().scalar_mul_const_time(&FieldElement::random_using_rng(&mut generator.rng));

    let f_hash = FieldElement::from_bytes(&hash[..]).map_err(|_| BBSError::from_kind(BBSErrorKind::KeyGenError))?;
    h0 = h0.scalar_mul_const_time(&f_hash);
    Ok((
        PublicKey {
            w,
            h0,
            h,
        },
        secret)
    )
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

    #[test]
    fn key_generate() {
        let res = generate(0);
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
        use rand::RngCore;
        let mut attributes = BTreeSet::new();
        attributes.insert("first_name".to_string());
        attributes.insert("last_name".to_string());
        attributes.insert("date_of_birth".to_string());
        attributes.insert("gender".to_string());
        let mut generator = DeterministicGenerator::new(&attributes, None);

        let res = generate_deterministically(&mut generator);
        assert!(res.is_ok());
        let (pk, sk) = res.unwrap();

        generator = DeterministicGenerator::new(&attributes, None);
        let res = generate_deterministically(&mut generator);
        assert!(res.is_ok());
        let (pk1, sk1) = res.unwrap();
        assert_eq!(pk, pk1);
        assert_eq!(sk, sk1);

        //Use a secret entropy value, this is the real secret key
        let mut rng = rand::thread_rng();
        let mut seed = vec![0u8; 64];
        rng.fill_bytes(seed.as_mut_slice());
        generator = DeterministicGenerator::new(&attributes, Some(seed.as_slice()));
        let res = generate_deterministically(&mut generator);
        assert!(res.is_ok());
        let (pk, sk) = res.unwrap();

        generator = DeterministicGenerator::new(&attributes, Some(seed.as_slice()));
        let res = generate_deterministically(&mut generator);
        assert!(res.is_ok());
        let (pk1, sk1) = res.unwrap();
        assert_eq!(pk, pk1);
        assert_eq!(sk, sk1);
    }
}
