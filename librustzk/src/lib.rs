extern crate bellman;
extern crate ff;
extern crate pairing;
extern crate rand;
extern crate sapling_crypto;

pub mod zk;

use std::os::raw::c_int;
use std::sync::Once;
use std::slice;

use bellman::groth16;
use ff::{BitIterator, PrimeField, PrimeFieldRepr, Field, ScalarEngine};
use pairing::bls12_381::{Bls12, Fr};
use sapling_crypto::jubjub::JubjubBls12;
use sapling_crypto::pedersen_hash;

fn read_field_from_c_ptr(ptr: *const u8) -> Fr {
    let mut fr_repr: <Fr as PrimeField>::Repr = 0.into();
    unsafe {
        fr_repr.read_le(slice::from_raw_parts(ptr, zk::HASH_SIZE)).unwrap();
    }
    Fr::from_repr(fr_repr).unwrap()
}

fn write_field_to_c_ptr(fr: &Fr, ptr: *mut u8) {
    unsafe {
        fr.into_repr().write_le(slice::from_raw_parts_mut(ptr, zk::HASH_SIZE)).unwrap()
    }
}

fn get_bls_params() -> &'static JubjubBls12 {
    static mut BLS_PARAMS: *const JubjubBls12 = std::ptr::null();
    static START: Once = Once::new();
    START.call_once(|| unsafe {
        BLS_PARAMS = Box::into_raw(Box::new(JubjubBls12::new()));
    });
    unsafe {
        &*BLS_PARAMS
    }
}

#[no_mangle]
pub unsafe extern "C" fn _jubjub_hash(
    personalization: c_int, // -1 for commitment, >= 0 for merkle tree
    fr_ptr_a: *const u8,
    fr_ptr_b: *const u8,
    out_ptr: *mut u8,
) {
    let fr_a = read_field_from_c_ptr(fr_ptr_a);
    let fr_b = read_field_from_c_ptr(fr_ptr_b);
    fn fr_to_bits_le(x: Fr) -> Vec<bool> {
        BitIterator::new(x.into_repr())
            .collect::<Vec<bool>>()
            .into_iter()
            .rev()
            .take(Fr::NUM_BITS as usize)
            .collect()
    }
    let preimage: Vec<bool> = fr_to_bits_le(fr_a)
        .into_iter()
        .chain(fr_to_bits_le(fr_b).into_iter())
        .collect();
    let personalization = match personalization {
        -1 => pedersen_hash::Personalization::NoteCommitment,
        x => pedersen_hash::Personalization::MerkleTree(x as usize),
    };

    let fr_out = pedersen_hash::pedersen_hash::<Bls12, _>(personalization, preimage, get_bls_params())
        .into_xy()
        .0;
    write_field_to_c_ptr(&fr_out, out_ptr);
}

#[no_mangle]
pub unsafe extern "C" fn _generate_pre_transfer_proof(
    commit_root: *const u8,
    commit_root_t: *const u8,
    addresses: *const *const u8,
    passphrase: *const u8,
    threshold: *const u8,
    address_new: *const u8,
    nonce: *const u8,
    params: *const u8,
    params_len: c_int,
    proof_out_buf: *mut u8,
    proof_out_len: c_int,
) {
    let addresses: Vec<Option<Fr>> = slice::from_raw_parts(addresses, zk::MAX_FRIENDS_LEN)
        .into_iter().map(|ptr| Some(read_field_from_c_ptr(*ptr))).collect();
    let instance = zk::PreTransferCircuit::<Bls12> {
        commit_root: Some(read_field_from_c_ptr(commit_root)),
        commit_root_t: Some(read_field_from_c_ptr(commit_root_t)),
        addresses: &addresses,
        passphrase: Some(read_field_from_c_ptr(passphrase)),
        threshold: Some(read_field_from_c_ptr(threshold)),
        address_new: Some(read_field_from_c_ptr(address_new)),
        nonce: Some(read_field_from_c_ptr(nonce)),
        params: get_bls_params(),
    };

    let proof_params = groth16::Parameters::<Bls12>::read(slice::from_raw_parts(params, params_len as usize), false).unwrap();
    let mut rng = rand::thread_rng();
    let proof = groth16::create_random_proof(instance, &proof_params, &mut rng).unwrap();
    proof.write(slice::from_raw_parts_mut(proof_out_buf, proof_out_len as usize)).unwrap();

    // check proof validity
    assert!(groth16::verify_proof(&groth16::prepare_verifying_key(&proof_params.vk), &proof, &vec![
        read_field_from_c_ptr(commit_root),
        read_field_from_c_ptr(commit_root_t),
        read_field_from_c_ptr(address_new),
        read_field_from_c_ptr(nonce)
    ]).unwrap());
}

#[no_mangle]
pub unsafe extern "C" fn _verify_pre_transfer_proof(
    commit_root: *const u8,
    commit_root_t: *const u8,
    address_new: *const u8,
    nonce: *const u8,
    proof: *const u8,
    proof_len: c_int,
    vk: *const u8,
    vk_len: c_int,
) -> c_int {
    let proof = groth16::Proof::<Bls12>::read(slice::from_raw_parts(proof, proof_len as usize)).unwrap();
    let vk = groth16::VerifyingKey::<Bls12>::read(slice::from_raw_parts(vk, vk_len as usize)).unwrap();
    let pvk = groth16::prepare_verifying_key(&vk);
    let inputs: Vec<Fr> = vec![commit_root, commit_root_t, address_new, nonce].into_iter().map(|x| read_field_from_c_ptr(x)).collect();
    if groth16::verify_proof(&pvk, &proof, &inputs).unwrap() {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn _generate_preparation_proof(
    commit_root: *const u8,
    friend_address: *const u8,
    friend_path: *const *const u8, 
    friend_directions: *const u8, // direction bytes
    passphrase: *const u8,
    threshold: *const u8,
    nonce: *const u8,
    verification: *const u8,
    pre_transfer_index: *const u8,
    verification_nonce1: *const u8,
    verification_nonce2: *const u8,
    verification_root: *const u8,
    verification_path: *const *const u8,
    verification_directions: *const u8,
    params: *const u8,
    params_len: c_int,
    proof_out_buf: *mut u8,
    proof_out_len: c_int,
) {
    let friend_path: Vec<Option<Fr>> = slice::from_raw_parts(
        friend_path, zk::FRIENDS_MERKLE_DEPTH
    ).into_iter().map(|ptr| Some(read_field_from_c_ptr(*ptr))).collect();
    let friend_directions: Vec<Option<bool>> = slice::from_raw_parts(
        friend_directions, zk::FRIENDS_MERKLE_DEPTH
    ).into_iter().map(|b| match b {
        0 => Some(false),
        _ => Some(true),
    }).collect();

    let verification_path: Vec<Option<Fr>> = slice::from_raw_parts(
        verification_path, zk::VERIFICATION_MERKLE_DEPTH
    ).into_iter().map(|ptr| Some(read_field_from_c_ptr(*ptr))).collect();
    let verification_directions: Vec<Option<bool>> = slice::from_raw_parts(
        verification_directions, zk::VERIFICATION_MERKLE_DEPTH
    ).into_iter().map(|b| match b {
        0 => Some(false),
         _ => Some(true),
    }).collect();
    
    let instance = zk::PreparationCircuit::<Bls12>{
        commit_root: Some(read_field_from_c_ptr(commit_root)),
        friend_address: Some(read_field_from_c_ptr(friend_address)),
        friend_path: &friend_path,
        friend_directions: &friend_directions,
        passphrase: Some(read_field_from_c_ptr(passphrase)),
        threshold: Some(read_field_from_c_ptr(threshold)),
        nonce: Some(read_field_from_c_ptr(nonce)),
        verification: Some(read_field_from_c_ptr(verification)),
        pre_transfer_index: Some(read_field_from_c_ptr(pre_transfer_index)),
        verification_nonce1: Some(read_field_from_c_ptr(verification_nonce1)),
        verification_nonce2: Some(read_field_from_c_ptr(verification_nonce2)),
        verification_root: Some(read_field_from_c_ptr(verification_root)),
        verification_path: &verification_path,
        verification_directions: &verification_directions,
        params: get_bls_params(),
    };

    let proof_params = groth16::Parameters::<Bls12>::read(slice::from_raw_parts(params, params_len as usize), false).unwrap();
    let mut rng = rand::thread_rng();
    let proof = groth16::create_random_proof(instance, &proof_params, &mut rng).unwrap();
    proof.write(slice::from_raw_parts_mut(proof_out_buf, proof_out_len as usize)).unwrap();

    let friend_directions_fr: Vec<Fr> = (&friend_directions).into_iter().map(|b| match b {
        Some(false) => <<Bls12 as ScalarEngine>::Fr as Field>::zero(),
        Some(true) => <<Bls12 as ScalarEngine>::Fr as Field>::one(),
        _ => panic!()
    }).collect(); 
    // check proof validity
    let mut inputs = vec![];
    inputs.push(read_field_from_c_ptr(commit_root));
    inputs.extend(friend_directions_fr);
    inputs.push(read_field_from_c_ptr(nonce));
    inputs.push(read_field_from_c_ptr(pre_transfer_index));
    inputs.push(read_field_from_c_ptr(verification_root));
    assert!(groth16::verify_proof(&groth16::prepare_verifying_key(&proof_params.vk), &proof, &inputs).unwrap());
}

#[no_mangle]
pub unsafe extern "C" fn _verify_preparation_proof(
    commit_root: *const u8,
    friend_directions: *const u8, // direction bytes
    nonce: *const u8,
    pre_transfer_index: *const u8,
    verification_root: *const u8,
    proof: *const u8,
    proof_len: c_int,
    vk: *const u8,
    vk_len: c_int,
) -> c_int {
    let proof = groth16::Proof::<Bls12>::read(slice::from_raw_parts(proof, proof_len as usize)).unwrap();
    let vk = groth16::VerifyingKey::<Bls12>::read(slice::from_raw_parts(vk, vk_len as usize)).unwrap();
    let pvk = groth16::prepare_verifying_key(&vk);

    let friend_directions_fr: Vec<Fr> = slice::from_raw_parts(friend_directions, zk::FRIENDS_MERKLE_DEPTH)
        .into_iter().map(|b| match b {
            0 => <Bls12 as ScalarEngine>::Fr::zero(),
            _ => <Bls12 as ScalarEngine>::Fr::one(),
        }
    ).collect(); 
    // check proof validity
    let mut inputs = vec![];
    inputs.push(read_field_from_c_ptr(commit_root));
    inputs.extend(friend_directions_fr);
    inputs.push(read_field_from_c_ptr(nonce));
    inputs.push(read_field_from_c_ptr(pre_transfer_index));
    inputs.push(read_field_from_c_ptr(verification_root));
    if groth16::verify_proof(&pvk, &proof, &inputs).unwrap() {
        return 1;
    } else {
        return 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn _generate_transfer_proof(
    commit_root: *const u8,
    vlist: *const u8,
    addresses: *const *const u8,
    passphrase: *const u8,
    threshold: *const u8,
    nonce: *const u8,
    params: *const u8,
    params_len: c_int,
    proof_out_buf: *mut u8,
    proof_out_len: c_int,
) {
    let vlist: Vec<Option<bool>> = slice::from_raw_parts(vlist, zk::MAX_FRIENDS_LEN)
        .into_iter()
        .map(|v| match v {
            0 => Some(false),
            _ => Some(true),
        }).collect();
    let addresses: Vec<Option<Fr>> = slice::from_raw_parts(addresses, zk::MAX_FRIENDS_LEN)
        .into_iter().map(|ptr| Some(read_field_from_c_ptr(*ptr))).collect();
    let instance = zk::TransferCircuit::<Bls12> {
        commit_root: Some(read_field_from_c_ptr(commit_root)),
        vlist: &vlist,
        addresses: &addresses,
        passphrase: Some(read_field_from_c_ptr(passphrase)),
        threshold: Some(read_field_from_c_ptr(threshold)),
        nonce: Some(read_field_from_c_ptr(nonce)),
        params: get_bls_params(),
    };

    let proof_params = groth16::Parameters::<Bls12>::read(slice::from_raw_parts(params, params_len as usize), false).unwrap();
    let mut rng = rand::thread_rng();
    let proof = groth16::create_random_proof(instance, &proof_params, &mut rng).unwrap();
    proof.write(slice::from_raw_parts_mut(proof_out_buf, proof_out_len as usize)).unwrap();

    // check proof validity
    let mut inputs = vec![];
    inputs.push(read_field_from_c_ptr(commit_root));
    inputs.extend((&vlist).into_iter()
        .map(|b| match b {
            Some(false) => Fr::zero(),
            Some(true) => Fr::one(),
            None => panic!()
        }).collect::<Vec<Fr>>());
    assert!(groth16::verify_proof(&groth16::prepare_verifying_key(&proof_params.vk), &proof, &inputs).unwrap());
}

#[no_mangle]
pub unsafe extern "C" fn _verify_transfer_proof(
    commit_root: *const u8,
    vlist: *const u8,
    proof: *const u8,
    proof_len: c_int,
    vk: *const u8,
    vk_len: c_int,
) -> c_int {
    let proof = groth16::Proof::<Bls12>::read(slice::from_raw_parts(proof, proof_len as usize)).unwrap();
    let vk = groth16::VerifyingKey::<Bls12>::read(slice::from_raw_parts(vk, vk_len as usize)).unwrap();
    let pvk = groth16::prepare_verifying_key(&vk);

    let vlist: Vec<Fr> = slice::from_raw_parts(vlist, zk::MAX_FRIENDS_LEN)
        .into_iter().map(|b| match b {
            0 => <Bls12 as ScalarEngine>::Fr::zero(),
            _ => <Bls12 as ScalarEngine>::Fr::one(),
        }).collect(); 
    // check proof validity
    let mut inputs = vec![];
    inputs.push(read_field_from_c_ptr(commit_root));
    inputs.extend(vlist);
    if groth16::verify_proof(&pvk, &proof, &inputs).unwrap() {
        return 1;
    } else {
        return 0;
    }
}