extern crate rand;
extern crate bellman;
extern crate sapling_crypto;
extern crate rustzk;
extern crate pairing;

use std::path::PathBuf;
use std::fs::File;
use rustzk::zk;
use sapling_crypto::jubjub::JubjubBls12;
use pairing::bls12_381::Bls12;
use bellman::{Circuit, groth16};

fn generate_params<C: Circuit<Bls12>>(instance: C, params_path: &str, vk_path: &str) {
    let rng = &mut rand::thread_rng();
    let params = groth16::generate_random_parameters(instance, rng).unwrap();

    let params_file = File::create(PathBuf::from(params_path)).unwrap();
    params.write(params_file).unwrap();

    let vk_file = File::create(PathBuf::from(vk_path)).unwrap();
    params.vk.write(vk_file).unwrap();
}


fn main() {
    let bls_params = JubjubBls12::new();

    let pre_transfer_instance = zk::PreTransferCircuit::<Bls12> {
        commit_root: None,
        commit_root_t: None,
        addresses: &vec![None; zk::MAX_FRIENDS_LEN],
        passphrase: None,
        threshold: None,
        address_new: None,
        nonce: None,
        params: &bls_params,
    };
    println!("generating pre-transfer params...");
    generate_params(pre_transfer_instance, "pre-transfer.params", "pre-transfer.vk");

    let preparation_instance = zk::PreparationCircuit::<Bls12>{
        commit_root: None,
        friend_address: None,
        friend_path: &vec![None; zk::FRIENDS_MERKLE_DEPTH],
        friend_directions: &vec![None; zk::FRIENDS_MERKLE_DEPTH],
        passphrase: None,
        threshold: None,
        nonce: None,
        verification: None,
        pre_transfer_index: None,
        verification_nonce1: None,
        verification_nonce2: None,
        verification_root: None,
        verification_path: &vec![None; zk::VERIFICATION_MERKLE_DEPTH],
        verification_directions: &vec![None; zk::VERIFICATION_MERKLE_DEPTH],
        params: &bls_params,
    };
    println!("generating preparation params...");
    generate_params(preparation_instance, "preparation.params", "preparation.vk");

    let transfer_instance = zk::TransferCircuit::<Bls12> {
        commit_root: None,
        vlist: &vec![None; zk::MAX_FRIENDS_LEN],
        addresses: &vec![None; zk::MAX_FRIENDS_LEN],
        passphrase: None,
        threshold: None,
        nonce: None,
        params: &bls_params,
    };
    println!("generating transfer params...");
    generate_params(transfer_instance, "transfer.params", "transfer.vk");
}


