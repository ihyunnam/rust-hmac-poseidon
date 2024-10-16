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

use core::borrow::Borrow;

use ark_crypto_primitives::{crh::{poseidon::{constraints::{CRHGadget, CRHParametersVar}, CRH}, CRHSchemeGadget}, sponge::Absorb};
use ark_r1cs_std::{alloc::{AllocVar, AllocationMode}, fields::fp::AllocatedFp, prelude::Boolean, uint8::UInt8, ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable};
use ark_std::{marker::PhantomData, println, time::Instant, vec::Vec, One};
use ark_ff::fields::{PrimeField, Field};
use ark_crypto_primitives::{sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig}};
use ark_crypto_primitives::crh::CRHScheme;
use ark_bn254::Fr;
// type F = Fr;
use ark_std::vec;
use ark_serialize::{CanonicalSerialize, Compress};

// #[derive(Copy, Clone)]
#[derive(Clone)]
pub struct Hash {
    params: PoseidonConfig<Fr>, // Parameters for the Poseidon hash
    buffer: Vec<Fr>,                // Buffer to store absorbed field elements
}

impl Hash {
    pub fn new(poseidon_params: &PoseidonConfig<Fr>) -> Hash {
        Hash {
            params: poseidon_params.clone(),
            buffer: vec![],
        }
    }

    fn _update(&mut self, input: impl AsRef<[u8]>) {
        // Convert input bytes to field elements and add to the buffer
        let input = input.as_ref();
        let mut field_elements: Vec<Fr> = input
            .chunks(32) // Split the input into chunks of the field size
            .map(Fr::from_be_bytes_mod_order) // Convert each chunk into a field element
            .collect();
        self.buffer.append(&mut field_elements); // Add field elements to the buffer
    }

    /// Absorb content
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self._update(input)
    }

    /// Compute SHA256(absorbed content)
    pub fn finalize(self) -> Fr {
        let hash_result = CRH::<Fr>::evaluate(&self.params, self.buffer).unwrap();
        // let mut writer = vec![];
        // hash_result.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
        // let mut output = [0u8; 32];
        // output[..32].copy_from_slice(&writer);

        hash_result
    }

    /// Compute Poseidon(`input`)
    pub fn hash(input: &[u8], poseidon_params: &PoseidonConfig<Fr>) -> Fr {
        let mut h = Hash::new(poseidon_params);
        h.update(input);
        h.finalize()
    }
}

impl Default for Hash {
    fn default() -> Self {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (255, 2, 8, 24, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 24, 31, mds, ark, 2, 1);
        Self::new(&poseidon_params)
    }
}

#[derive(Clone)]
pub struct HMAC {
    ih: Hash,
    padded: [u8; 64],
}

impl HMAC {
    /// Compute HMAC-Poseidon(`input`, `k`)
    pub fn mac(input: impl AsRef<[u8]>, k: impl AsRef<[u8]>, poseidon_params: &PoseidonConfig<Fr>) -> Fr {
        // let start = Instant::now();
        let input = input.as_ref();
        let k = k.as_ref();
        let mut hk = [0u8; 32];
        let k2 = if k.len() > 64 {
            println!("inside if?");
            // let start = Instant::now();
            let hash_fr = &Hash::hash(k, poseidon_params);
            let mut writer = vec![];
            hash_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
            hk[..32].copy_from_slice(&writer);
            // hk.copy_from_slice(&Hash::hash(k, poseidon_params));
            // let end = start.elapsed();
            // println!("time to hash {:?}", end);
            //println!("after copy");
            &hk
        } else {
            k
        };
        let mut padded = [0x36; 64];
        
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let start = Instant::now();
        let mut ih = Hash::new(poseidon_params);
        let end = start.elapsed();
        println!("just new {:?}", end);
        //println!("before ih update");
        ih.update(&padded[..]);
        ih.update(input);
        //println!("after ih update");

        for p in padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Hash::new(poseidon_params);
        //println!("before oh update");
        oh.update(&padded[..]);
        let ih_fr = ih.finalize();
        let mut writer = vec![];
        ih_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
        // let mut output = [0u8; 32];
        // output[..32].copy_from_slice(&writer);
        oh.update(writer);
        //println!("after oh update");
        oh.finalize()
    }

    pub fn new(k: impl AsRef<[u8]>, poseidon_params: &PoseidonConfig<Fr>) -> HMAC {
        let k = k.as_ref();
        let mut hk = [0u8; 32];
        let k2 = if k.len() > 64 {
            let hash_fr = &Hash::hash(k, poseidon_params);
            let mut writer = vec![];
            hash_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
            hk[..32].copy_from_slice(&writer);
            &hk
        } else {
            k
        };
        let mut padded = [0x36; 64];
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        let mut ih = Hash::new(poseidon_params);
        ih.update(&padded[..]);
        HMAC { ih, padded }
    }

    /// Absorb content
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.ih.update(input);
    }

    /// Compute HMAC-Poseidon over the entire input
    pub fn finalize(mut self, poseidon_params: &PoseidonConfig<Fr>) -> Fr {
        for p in self.padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Hash::new(poseidon_params);
        oh.update(&self.padded[..]);
        
        let ih_fr = self.ih.finalize();
        let mut writer = vec![];
        ih_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
        // let mut output = [0u8; 32];
        // output[..32].copy_from_slice(&writer);

        oh.update(writer);
        oh.finalize()
    }
}

// Variable version of Hash to work within R1CS
#[derive(Clone)]
pub struct HashVar<F: PrimeField + Absorb> {
    params: CRHParametersVar<F>, // Parameters variable
    buffer: Vec<FpVar<F>>, // Buffer for absorbed elements
}

impl<F: PrimeField + Absorb> HashVar<F> {
    pub fn new(
        cs: impl Into<Namespace<F>>, 
        poseidon_params: &CRHParametersVar<F>
    ) -> Result<Self, SynthesisError> {
        Ok(HashVar {
            params: poseidon_params.clone(),
            buffer: vec![], // Initialize buffer
        })
    }

    fn _update(&mut self, input: &[FpVar<F>]) {
        // Add input elements to the buffer
        self.buffer.extend_from_slice(input);
    }

    pub fn update(&mut self, input: &[FpVar<F>]) {
        self._update(input)
    }

    // pub fn finalize1(self) -> [u8; 32] {
    //     let hash_result = CRH::<Fr>::evaluate(&self.params, self.buffer).unwrap();
    //     let mut writer = vec![];
    //     hash_result.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
    //     let mut output = [0u8; 32];
    //     output[..32].copy_from_slice(&writer);

    //     output
    // }
    
    pub fn finalize(&self) -> Result<FpVar<F>, SynthesisError> {
        let hash_result = CRHGadget::<F>::evaluate(&self.params, &self.buffer)?;
        // let mut writer = vec![];
        // hash_result.serialize_with_mode(&mut writer, Compress::Yes).unwrap();

        // // Convert serialized hash result to UInt8 representation
        // let hash_bytes = writer
        //     .into_iter()
        //     .map(|b| UInt8::constant(b))
        //     .collect::<Vec<_>>();

        Ok(hash_result)
    }

    pub fn hash(
        cs: impl Into<Namespace<F>>,
        input: &[FpVar<F>],
        poseidon_params: &CRHParametersVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        let mut h = HashVar::new(cs, poseidon_params)?;
        h.update(input);
        h.finalize()
    }
}

#[derive(Clone)]
pub struct HMACGadget<F: PrimeField + Absorb> {
    ih: HashVar<F>,
    padded: Vec<UInt8<F>>, // UInt8 for bytes in R1CS
}

impl<F: PrimeField + Absorb> HMACGadget<F> {
    pub fn mac(
        // cs: impl Into<Namespace<F>>,
        cs: ConstraintSystemRef<F>,
        input: &[FpVar<F>],
        k: &[FpVar<F>],
        poseidon_params: &CRHParametersVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        // let cs = cs.into(); 

        let input = input.as_ref();
        let k = k.as_ref();
        // let mut hk = [0u8; 32];
        // let k2 = if k.len() > 64 {       // TODO: just make sure k<64
        //     let hash_fr = &HashVar::hash(cs.clone(), k, poseidon_params).unwrap();
        //     let mut writer = vec![];
        //     hash_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
        //     hk[..32].copy_from_slice(&writer);
        //     // hk.copy_from_slice(&Hash::hash(k, poseidon_params));
        //     // let end = start.elapsed();
        //     // println!("time to hash {:?}", end);
        //     //println!("after copy");
        //     &hk
        // } else {
        //     k
        // };

        let mut k2 = vec![];
        for elem in k {
            k2.append(&mut elem.to_bytes().unwrap());
        }
        let mut padded = vec![UInt8::<F>::constant(0x36); 64];
        
        for (p, k) in padded.iter_mut().zip(k2.iter()) {
            // let k_flat = vec![];
            // for elem in k {
            //     k_flat.push(elem);
            // }
            *p = p.xor(k).unwrap();
        }

        // Create the inner hash instance and update it with padded and input
        let mut ih = HashVar::new(cs.clone(), poseidon_params)?;
        // for elem in padded {
        let padded_fr = from_bytes_le(cs.clone(), &padded).unwrap();
        // }
        // let padded_fr = FpVar::<F>::from(padded.to_bits_be().unwrap());
        ih.update(&[padded_fr.into()]);
        // ih.update(&input.iter().map(|byte| byte).collect::<Result<Vec<_>, _>>()?);
        ih.update(&input);

        // Adjust padded for the outer hash
        for p in padded.iter_mut() {
            *p = p.xor(&UInt8::<F>::constant(0x6a)).unwrap();
        }

        // Create the out er hash instance
        let padded_fr = from_bytes_le(cs.clone(), &padded).unwrap();
        let mut oh = HashVar::new(cs.clone(), poseidon_params)?;
        oh.update(&[padded_fr.into()]);
        // oh.update(&padded.iter().map(|byte| byte).collect::<Result<Vec<_>, _>>()?);
        oh.update(&[ih.finalize().unwrap()]);

        oh.finalize()
    }
}

/// Reconstructs `AllocatedFp<F>` from its little-endian byte representation.
pub fn from_bytes_le<F: PrimeField + Absorb> (cs: ConstraintSystemRef<F>, bytes: &Vec<UInt8<F>>) -> Result<AllocatedFp<F>, SynthesisError> {
    // Convert bytes to bits in little-endian order
    let mut bits: Vec<Boolean<F>> = Vec::new();
    for byte in bytes.iter() {
        bits.extend_from_slice(&byte.to_bits_le()?);
    }

    // Create a linear combination from the bits
    let mut lc = LinearCombination::zero();
    let mut coeff = F::one();

    for bit in bits {
        match bit {
            Boolean::Constant(b) => {
                if b {
                    lc += (coeff, Variable::One);
                }
            }
            Boolean::Is(var) => {
                lc += (coeff, var.variable());
            }
            Boolean::Not(var) => {
                lc = lc + (coeff, Variable::One) - (coeff, var.variable());
            }
        }
        coeff.double_in_place(); // Each bit represents an increasing power of 2
    }

    // Allocate a new variable in the constraint system using the linear combination
    let variable = cs.new_lc(lc)?;

    // Return the newly constructed AllocatedFp
    Ok(AllocatedFp::new(None, variable, cs))
}

impl<F: PrimeField + Absorb> AllocVar<HashVar<F>, F> for HashVar<F> {
    fn new_variable<T: Borrow<HashVar<F>>>(
        cs: impl Into<Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let hash = f()?.borrow().clone();
        Ok(HashVar {
            params: hash.params,
            buffer: hash.buffer,
        })
    }
}
