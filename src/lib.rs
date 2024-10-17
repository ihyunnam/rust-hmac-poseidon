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
use ark_r1cs_std::{R1CSVar, alloc::{AllocVar, AllocationMode}, fields::fp::AllocatedFp, prelude::Boolean, uint8::UInt8, ToBitsGadget, ToBytesGadget};
use ark_r1cs_std::fields::{FieldVar, fp::FpVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, LinearCombination, Namespace, SynthesisError, Variable};
use ark_std::{marker::PhantomData, println, time::Instant, vec::Vec, One};
use ark_ff::{fields::{Field, PrimeField}, BigInt, BigInteger};
use ark_crypto_primitives::{sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig}};
use ark_crypto_primitives::crh::CRHScheme;
use ark_bls12_377::Fr;
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
        // I think field size is 377 for bls12-377??

        // let mut field_elements: Vec<Fr> = input
        //     .chunks(32) // Split the input into chunks of the field size
        //     .map(Fr::from_be_bytes_mod_order) // Convert each chunk into a field element
        //     .collect();
        let field_element: Fr = Fr::from_le_bytes_mod_order(input);
        self.buffer.push(field_element); // Add field elements to the buffer
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

/* Not used in code. */
impl Default for Hash {
    fn default() -> Self {
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr> (255, 2, 8, 31, 0);        // ark_bn254::FrParameters::MODULUS_BITS = 255
        let poseidon_params = PoseidonConfig::<Fr>::new(8, 31, 17, mds, ark, 2, 1);
        Self::new(&poseidon_params)
    }
}

#[derive(Clone)]
pub struct HMAC {
    ih: Hash,
    padded: [u8; 64],
}

impl HMAC {     // THE THINGS WE HMAC ARE BOTH Fr (h_i, v_i)
    /// Compute HMAC-Poseidon(`input`, `k`)
    pub fn mac(input: Vec<Fr>, k: Fr, poseidon_params: &PoseidonConfig<Fr>) -> Fr {
        // let start = Instant::now();
        // let input = input.as_ref();
        // let k = k.as_ref();
        // let mut hk = [0u8; 32];
        // let k2 = if k.len() > 64 {
        //     println!("inside if?"); // I don't think this gets triggered
        //     // let start = Instant::now();
        //     let hash_fr = &Hash::hash(k, poseidon_params);
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
        k.serialize_compressed(&mut k2);
        // TODO: just make sure k: Fr gets serialized to length <64
        let mut padded = [0x36; 64];
        
        for (p, &k) in padded.iter_mut().zip(k2.iter()) {
            *p ^= k;
        }
        // let start = Instant::now();
        let mut ih = Hash::new(poseidon_params);
        // let end = start.elapsed();
        // println!("just new {:?}", end);
        //println!("before ih update");
        ih.update(&padded[..]);
        // ih.update(input);

        ih.buffer.extend(input);   // instead of ih.update(input) push input to buffer directly because input already Fr
        //println!("after ih update");

        for p in padded.iter_mut() {
            *p ^= 0x6a;
        }
        let mut oh = Hash::new(poseidon_params);
        //println!("before oh update");
        oh.update(&padded[..]);
        // let ih_fr = ih.finalize();
        oh.buffer.push(ih.finalize());  // since ih.finalize() returns Fr already, push instead of oh.update
        // let mut writer = vec![];
        // ih_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
        // oh.update(writer);
        //println!("after oh update");
        oh.finalize()
    }

    /* originally only used in HKDF */
    // pub fn new(k: impl AsRef<[u8]>, poseidon_params: &PoseidonConfig<Fr>) -> HMAC {
    //     let k = k.as_ref();
    //     let mut hk = [0u8; 32];
    //     let k2 = if k.len() > 64 {
    //         let hash_fr = &Hash::hash(k, poseidon_params);
    //         let mut writer = vec![];
    //         hash_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
    //         hk[..32].copy_from_slice(&writer);
    //         &hk
    //     } else {
    //         k
    //     };
    //     let mut padded = [0x36; 64];
    //     for (p, &k) in padded.iter_mut().zip(k2.iter()) {
    //         *p ^= k;
    //     }
    //     let mut ih = Hash::new(poseidon_params);
    //     ih.update(&padded[..]);
    //     HMAC { ih, padded }
    // }

    /// Absorb content
    pub fn update(&mut self, input: impl AsRef<[u8]>) {
        self.ih.update(input);
    }

    /* originally only used in HKDF */
    // /// Compute HMAC-Poseidon over the entire input
    // pub fn finalize(mut self, poseidon_params: &PoseidonConfig<Fr>) -> Fr {
    //     for p in self.padded.iter_mut() {
    //         *p ^= 0x6a;
    //     }
    //     let mut oh = Hash::new(poseidon_params);
    //     oh.update(&self.padded[..]);
        
    //     let ih_fr = self.ih.finalize();
    //     let mut writer = vec![];
    //     ih_fr.serialize_with_mode(&mut writer, Compress::Yes); // Convert the result to bytes
    //     // let mut output = [0u8; 32];
    //     // output[..32].copy_from_slice(&writer);

    //     oh.update(writer);
    //     oh.finalize()
    // }
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

    fn _update(&mut self, input: &[UInt8<F>], cs: ConstraintSystemRef<F>) {
        // Add input elements to the buffer
        let input_bits: Vec<Boolean<F>> = input.to_bits_le().unwrap();       // TODO: NOT SURE IF CORRECT
        let input_fr = from_bits(cs.clone(), input_bits);
        // let input_bigint = BigInteger::from_bits_le(input_bits.as_slice());

        // let input_F: F = F::from(input_bits[0]);
        // F::from_bigint(input_bigint).unwrap();
        // let field_element: FpVar<F> = FpVar::constant(input_F);
        self.buffer.push(input_fr);
    }

    pub fn update(&mut self, input: &[UInt8<F>], cs: ConstraintSystemRef<F>) {
        self._update(input, cs)
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

    /* not used */
    // pub fn hash(
    //     cs: impl Into<Namespace<F>>,
    //     input: &[FpVar<F>],
    //     poseidon_params: &CRHParametersVar<F>,
    // ) -> Result<FpVar<F>, SynthesisError> {
    //     let mut h = HashVar::new(cs, poseidon_params)?;
    //     h.update(input);
    //     h.finalize()
    // }
}

#[derive(Clone)]
pub struct HMACGadget<F: PrimeField + Absorb> {
    ih: HashVar<F>,
    padded: Vec<UInt8<F>>, // UInt8 for bytes in R1CS
}

impl<F: PrimeField + Absorb> HMACGadget<F> {
    pub fn mac(
        cs: ConstraintSystemRef<F>,
        input: Vec<FpVar<F>>,
        k: FpVar<F>,
        poseidon_params: &CRHParametersVar<F>,
    ) -> Result<FpVar<F>, SynthesisError> {
        // let cs = cs.into(); 
        let k2: Vec<UInt8<F>> = k.to_bytes().unwrap();     // bigint->to_bytes_le under the hood. // TODO: check compressed or not.

        // TODO: just make sure k: Fr gets serialized to length <64
        let padded = [0x36; 64];        // does this need to be uint8<f> as well?
        let mut padded_var: Vec<UInt8<F>> = padded.iter().map(|&b| UInt8::<F>::constant(b)).collect();
        for (p, k) in padded_var.iter_mut().zip(k2.iter()) {
            p.xor(k).unwrap();
        }
        let mut ih = HashVar::new(cs.clone(), poseidon_params).unwrap();
        ih.update(&padded_var[..], cs.clone());

        ih.buffer.extend(input);   // instead of ih.update(input) push input to buffer directly because input already Fr

        let uint_var = UInt8::<F>::constant(0x6a);
        for p in padded_var.iter_mut() {
            p.xor(&uint_var).unwrap();
        }
        let mut oh = HashVar::new(cs.clone(), poseidon_params).unwrap();
        oh.update(&padded_var[..], cs.clone());
        oh.buffer.push(ih.finalize().unwrap());  // since ih.finalize() returns Fr already, push instead of oh.update
        oh.finalize()
    }
}

/* I think I made this and it's probably hella slow... DO NOT USE */
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

    // lc is now the number represented by bits
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

fn from_bits<F: PrimeField>(
    cs: ConstraintSystemRef<F>, 
    elem_bits: Vec<Boolean<F>>
) -> FpVar<F> {
    // let elem_bits: Vec<Boolean<Fr>> = elem_uint.to_bits_le().unwrap();
    // Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&elem_bits)).unwrap();

    // let cs = other.cs();
    let mut lc: LinearCombination<_> = LinearCombination::zero();
    let mut coeff = F::one();

    for bit in elem_bits.clone() {
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
        coeff.square_in_place(); // Each bit represents an increasing power of 2
    }

    // lc is now the number represented by bits
    // Allocate a new variable in the constraint system using the linear combination
    let variable = cs.new_lc(lc).unwrap();
    // let variable = cs.new_lc(elem_bits.lc()).unwrap();
    let recovered_fr = FpVar::Var(AllocatedFp::new(
        F::from_bigint(BigInteger::from_bits_le(&elem_bits.value().unwrap())),
        variable,
        cs,
    ));

    // let result = elem_var.is_eq(&recovered_fr).unwrap().value();

    recovered_fr
}