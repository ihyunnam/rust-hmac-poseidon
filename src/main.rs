use ark_r1cs_std::R1CSVar;
use ark_bls12_377::Fr;
use ark_crypto_primitives::sponge::Absorb;
use ark_ff::{BigInteger, PrimeField, UniformRand, Field};
use ark_r1cs_std::{eq::EqGadget, alloc::{AllocVar, AllocationMode}, fields::fp::{AllocatedFp, FpVar}, prelude::Boolean, uint8::UInt8, ToBitsGadget, ToBytesGadget};
use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef, LinearCombination, SynthesisError, Variable};
use ark_std::{One, Zero};
// fn from_bytes_le<F: PrimeField + Absorb> (cs: ConstraintSystemRef<F>, bytes: &Vec<UInt8<F>>) -> Result<FpVar<F>, SynthesisError> {
//     // Convert bytes to bits in little-endian order
//     let mut bits: Vec<Boolean<F>> = Vec::new();
//     for byte in bytes.iter() {
//         bits.extend_from_slice(&byte.to_bits_le()?);
//     }

//     // Create a linear combination from the bits
//     let mut lc = LinearCombination::zero();
//     let mut coeff = F::one();

//     for bit in bits {
//         match bit {
//             Boolean::Constant(b) => {
//                 if b {
//                     lc += (coeff, Variable::One);
//                 }
//             }
//             Boolean::Is(var) => {
//                 lc += (coeff, var.variable());
//             }
//             Boolean::Not(var) => {
//                 lc = lc + (coeff, Variable::One) - (coeff, var.variable());
//             }
//         }
//         coeff.double_in_place(); // Each bit represents an increasing power of 2
//     }

//     // lc is now the number represented by bits
//     // Allocate a new variable in the constraint system using the linear combination
//     let variable = cs.new_lc(lc)?;

//     // Return the newly constructed AllocatedFp
//     Ok(FpVar::<F>::from(variable))
// }

fn main() {
    let mut test_rng = ark_std::test_rng();
    let cs = ConstraintSystem::<Fr>::new_ref();
    let elem = Fr::rand(&mut test_rng);
    let elem_var = FpVar::<Fr>::new_variable(cs.clone(), || Ok(elem), AllocationMode::Witness).unwrap();
    let elem_uint = elem_var.to_bytes().unwrap();
    // println!("original fr {:?}", elem);
    // let recovered_fr: FpVar<Fr> = from_bytes_le(cs.clone(), &elem_uint).unwrap();
    let elem_bits: Vec<Boolean<Fr>> = elem_uint.to_bits_le().unwrap();
    // Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_le(&elem_bits)).unwrap();

    // let cs = other.cs();
    let mut lc: LinearCombination<_> = LinearCombination::zero();
    let mut coeff = Fr::one();

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
        <Fr as PrimeField>::from_bigint(BigInteger::from_bits_le(&elem_bits.value().unwrap())),
        variable,
        cs,
    ));

    let result = elem_var.is_eq(&recovered_fr).unwrap().value();
    println!("result {:?}", result);
}