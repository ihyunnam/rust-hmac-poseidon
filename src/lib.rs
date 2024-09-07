//! A small, self-contained SHA256 and HMAC-SHA256 implementation
//! (C) Frank Denis <fdenis [at] fastly [dot] com>, public domain

#![no_std]
#![allow(
    non_snake_case,
    clippy::cast_lossless,
    clippy::eq_op,
    clippy::identity_op,
    clippy::many_single_char_names,
    clippy::unreadable_literal
)]

use ark_crypto_primitives::crh::poseidon::{CRH, constraints::CRHGadget};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{marker::PhantomData, println, vec::Vec};
use ark_ff::fields::PrimeField;
use ark_crypto_primitives::{sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig}};
use ark_crypto_primitives::crh::CRHScheme;
use ark_bls12_381::Fr;
use ark_std::vec;
use ark_serialize::{CanonicalSerialize, Compress};

// #[derive(Copy, Clone)]
#[derive(Clone)]
pub struct Hash {
    params: PoseidonConfig<Fr>, // Parameters for the Poseidon hash
    buffer: Vec<Fr>,                // Buffer to store absorbed field elements
}

impl Hash {
    pub fn new() -> Hash {
        //println!("inside new");
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (255, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
        //println!("after ark, mds");
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        Hash {
            params: poseidon_params,
            buffer: vec![],
        }
    }

    fn _update(&mut self, input: impl AsRef<[u8]>) {
        // Convert input bytes to field elements and add to the buffer
        //println!("inside update");
        let input = input.as_ref();
        let mut field_elements: Vec<Fr> = input
            .chunks(32) // Split the input into chunks of the field size
            .map(Fr::from_be_bytes_mod_order) // Convert each chunk into a field element
            .collect();
        self.buffer.append(&mut field_elements); // Add field elements to the buffer
        //println!("end of update");
        // let input = input.as_ref();
        // let mut n = input.len();
        // self.len += n;
        // let av = 64 - self.r;
        // let tc = ::core::cmp::min(n, av);
        // self.w[self.r..self.r + tc].copy_from_slice(&input[0..tc]);
        // self.r += tc;
        // n -= tc;
        // let pos = tc;
        // if self.r == 64 {
        //     self.state.blocks(&self.w);
        //     self.r = 0;
        // }
        // if self.r == 0 && n > 0 {
        //     let rb = self.state.blocks(&input[pos..]);
        //     if rb > 0 {
        //         self.w[..rb].copy_from_slice(&input[pos + n - rb..]);
        //         self.r = rb;
        //     }
        // }
    }

    /// Absorb content
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self._update(input)
    }

    /// Compute SHA256(absorbed content)
    pub fn finalize(self) -> [u8; 32] {
        // let mut padded = [0u8; 128];
        // padded[..self.r].copy_from_slice(&self.w[..self.r]);
        // padded[self.r] = 0x80;
        // let r = if self.r < 56 { 64 } else { 128 };
        // let bits = self.len * 8;
        // for i in 0..8 {
        //     padded[r - 8 + i] = (bits as u64 >> (56 - i * 8)) as u8;
        // }
        // self.state.blocks(&padded[..r]);
        // let mut out = [0u8; 32];
        // self.state.store(&mut out);
        // out
        //println!("inside finalize");
        let hash_result = CRH::<Fr>::evaluate(&self.params, self.buffer).unwrap();
        let mut writer = vec![];
        hash_result.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
        let mut output = [0u8; 32];
        // let bytes = &writer[..32.min(writer.len())]; // Take the first 32 bytes or less
        output[..32].copy_from_slice(&writer);
        //println!("end of finalize");
        output
    }

    /// Compute Poseidon(`input`)
    pub fn hash(input: &[u8]) -> [u8; 32] {
        let mut h = Hash::new();
        h.update(input);
        h.finalize()
    }
}

impl Default for Hash {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
pub struct HMAC {
    ih: Hash,
    padded: [u8; 64],
}

impl HMAC {
    /// Compute HMAC-Poseidon(`input`, `k`)
    pub fn mac(input: impl AsRef<[u8]>, k: impl AsRef<[u8]>) -> [u8; 32] {
        let input = input.as_ref();
        let k = k.as_ref();
        let mut hk = [0u8; 32];
        let k2 = if k.len() > 64 {
            //println!("before copy");
            hk.copy_from_slice(&Hash::hash(k));
            //println!("after copy");
            &hk
        } else {
            k
        };
        let mut padded = [0x36; 64];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut ih = Hash::new();
        //println!("before ih update");
        ih.update(&padded[..]);
        ih.update(input);
        //println!("after ih update");

        for p in padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Hash::new();
        //println!("before oh update");
        oh.update(&padded[..]);
        oh.update(ih.finalize());
        //println!("after oh update");
        oh.finalize()
    }

    pub fn new(k: impl AsRef<[u8]>) -> HMAC {
        let k = k.as_ref();
        let mut hk = [0u8; 32];
        let k2 = if k.len() > 64 {
            hk.copy_from_slice(&Hash::hash(k));
            &hk
        } else {
            k
        };
        let mut padded = [0x36; 64];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut ih = Hash::new();
        ih.update(&padded[..]);
        HMAC { ih, padded }
    }

    /// Absorb content
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.ih.update(input);
    }

    /// Compute HMAC-Poseidon over the entire input
    pub fn finalize(mut self) -> [u8; 32] {
        for p in self.padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Hash::new();
        oh.update(&self.padded[..]);
        oh.update(self.ih.finalize());
        oh.finalize()
    }
}

pub struct HKDF;

impl HKDF {
    pub fn extract(salt: impl AsRef<[u8]>, ikm: impl AsRef<[u8]>) -> [u8; 32] {
        HMAC::mac(ikm, salt)
    }

    pub fn expand(out: &mut [u8], prk: impl AsRef<[u8]>, info: impl AsRef<[u8]>) {
        let info = info.as_ref();
        let mut counter: u8 = 1;
        assert!(out.len() < 0xff * 32);
        let mut i: usize = 0;
        while i < out.len() {
            let mut hmac = HMAC::new(&prk);
            if i != 0 {
                hmac.update(&out[i - 32..][..32]);
            }
            hmac.update(info);
            hmac.update([counter]);
            let left = core::cmp::min(32, out.len() - i);
            out[i..][..left].copy_from_slice(&hmac.finalize()[..left]);
            counter += 1;
            i += 32;
        }
    }
}

#[test]
fn main() {
    let h = HMAC::mac([], [0u8; 32]);
    assert_eq!(
        &h[..],
        &[
            182, 19, 103, 154, 8, 20, 217, 236, 119, 47, 149, 215, 120, 195, 95, 197, 255, 22, 151,
            196, 147, 113, 86, 83, 198, 199, 18, 20, 66, 146, 197, 173
        ]
    );

    let h = HMAC::mac([42u8; 69], []);
    assert_eq!(
        &h[..],
        &[
            225, 88, 35, 8, 78, 185, 165, 6, 235, 124, 28, 250, 112, 124, 159, 119, 159, 88, 184,
            61, 7, 37, 166, 229, 71, 154, 83, 153, 151, 181, 182, 72
        ]
    );

    let h = HMAC::mac([69u8; 250], [42u8; 50]);
    assert_eq!(
        &h[..],
        &[
            112, 156, 120, 216, 86, 25, 79, 210, 155, 193, 32, 120, 116, 134, 237, 14, 198, 1, 64,
            41, 124, 196, 103, 91, 109, 216, 36, 133, 4, 234, 218, 228
        ]
    );

    let mut s = HMAC::new([42u8; 50]);
    s.update([69u8; 150]);
    s.update([69u8; 100]);
    let h = s.finalize();
    assert_eq!(
        &h[..],
        &[
            112, 156, 120, 216, 86, 25, 79, 210, 155, 193, 32, 120, 116, 134, 237, 14, 198, 1, 64,
            41, 124, 196, 103, 91, 109, 216, 36, 133, 4, 234, 218, 228
        ]
    );

    let ikm = [0x0bu8; 22];
    let salt = [
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
    ];
    let context = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
    let prk = HKDF::extract(salt, ikm);
    let mut k = [0u8; 40];
    HKDF::expand(&mut k, prk, context);
    assert_eq!(
        &k[..],
        &[
            60, 178, 95, 37, 250, 172, 213, 122, 144, 67, 79, 100, 208, 54, 47, 42, 45, 45, 10,
            144, 207, 26, 90, 76, 93, 176, 45, 86, 236, 196, 197, 191, 52, 0, 114, 8, 213, 184,
            135, 24
        ]
    );
}
