use bellman::{Circuit, ConstraintSystem, SynthesisError};
use sapling_crypto::circuit::{boolean, num, pedersen_hash::pedersen_hash, pedersen_hash::Personalization};
use sapling_crypto::circuit::pedersen_hash::Personalization::{NoteCommitment, MerkleTree};
use sapling_crypto::jubjub::JubjubEngine;
use ff::{Field, PrimeField};

pub const FRIENDS_MERKLE_DEPTH: usize = 4;
pub const VERIFICATION_MERKLE_DEPTH: usize = 32;
pub const MAX_FRIENDS_LEN: usize = 1 << FRIENDS_MERKLE_DEPTH;
pub const HASH_SIZE: usize = 32;

pub struct PreTransferCircuit<'a, E: JubjubEngine> {
    pub commit_root: Option<E::Fr>,       // public
    pub commit_root_t: Option<E::Fr>,     // public
    pub addresses: &'a [Option<E::Fr>],   // private
    pub passphrase: Option<E::Fr>,  // take utf-8 encoded string as little-endian num, private
    pub threshold: Option<E::Fr>,   // private
    pub address_new: Option<E::Fr>, // public
    pub nonce: Option<E::Fr>,       // public

    pub params: &'a E::Params,
}

pub struct PreparationCircuit<'a, E: JubjubEngine> {
    pub commit_root: Option<E::Fr>,              // public
    pub friend_address: Option<E::Fr>,           // private
    pub friend_path: &'a [Option<E::Fr>],        // private
    pub friend_directions: &'a [Option<bool>],   // public, publicize as [Fr]
    pub passphrase: Option<E::Fr>,  // take utf-8 encoded string as little-endian num, private
    pub threshold: Option<E::Fr>,    // private
    pub nonce: Option<E::Fr>,        // public    
    pub verification: Option<E::Fr>, // private
    pub pre_transfer_index: Option<E::Fr>,  // public
    pub verification_nonce1: Option<E::Fr>, // private
    pub verification_nonce2: Option<E::Fr>,  // private
    pub verification_root: Option<E::Fr>,   // public
    pub verification_path: &'a [Option<E::Fr>],   // private
    pub verification_directions: &'a [Option<bool>],   // private

    pub params: &'a E::Params,
}

pub struct TransferCircuit<'a, E: JubjubEngine> {
    pub commit_root: Option<E::Fr>,     // public
    pub vlist: &'a [Option<bool>],      // public, exposed as [Fr]
    pub addresses: &'a [Option<E::Fr>],  // private
    pub passphrase: Option<E::Fr>,      // private
    pub threshold: Option<E::Fr>,       // private
    pub nonce: Option<E::Fr>,           // private

    pub params: &'a E::Params,
}

pub fn enforce_boolean_vec_equal<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    v1: &[boolean::Boolean],
    v2: &[boolean::Boolean],
) {
    assert!(v1.len() == v2.len());
    for (i, (a, b)) in v1.into_iter().zip(v2.into_iter()).enumerate() {
        boolean::Boolean::enforce_equal(cs.namespace(|| format!("bit {}", i)), a, b).unwrap();
    }
}

pub fn combine_hash<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    personalization: Personalization,
    xl: &num::AllocatedNum<E>,
    xr: &num::AllocatedNum<E>,
    params: &E::Params,
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let mut preimage = vec![];
    preimage.extend(xl.into_bits_le(cs.namespace(|| "xl into bits"))?);
    preimage.extend(xr.into_bits_le(cs.namespace(|| "xr into bits"))?);
    Ok(pedersen_hash(
        cs.namespace(|| "computation of pederson hash"),
        personalization,
        &preimage,
        params,
    )?.get_x().clone())
}

pub fn merkle_root_from_path<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    leaf: &num::AllocatedNum<E>,
    auth_path: &[(num::AllocatedNum<E>, boolean::Boolean)],
    params: &E::Params,
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let mut cur = leaf.clone();
    for (i, path) in auth_path.into_iter().enumerate() {
        let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));
        let (path_element, cur_is_right) = &path;
        let (xl, xr) = num::AllocatedNum::conditionally_reverse(
            cs.namespace(|| "conditional reversal of preimage"),
            &cur,
            path_element,
            cur_is_right,
        )?;
        cur = combine_hash(
            cs.namespace(|| "computation of pederson hash"), 
            MerkleTree(i), &xl, &xr, params
        )?;
    }
    Ok(cur.clone())
}

pub fn bulid_merkle_tree<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    leaves: &[num::AllocatedNum<E>],
    params: &E::Params,
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let mut cur = leaves.to_vec();
    let mut level = 0;
    while cur.len() != 1 {
        let prev = cur;
        assert_eq!(prev.len() % 2, 0);
        cur = vec![];
        for i in 0..prev.len() / 2 {
            cur.push(
                combine_hash(
                    cs.namespace(|| format!("level {}: hash{}", level, i)),
                    MerkleTree(level), &prev[2 * i], &prev[2 * i + 1], params
                )?
            );
        }
        level += 1;
    }
    Ok(cur[0].clone())
}

impl<'a, E: JubjubEngine> Circuit<E> for PreTransferCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // public input: commit_root
        let commit_root = num::AllocatedNum::alloc(cs.namespace(|| "commit_root"), || {
            Ok(self.commit_root.unwrap())
        })?;
        commit_root.inputize(cs.namespace(|| "commit_root(public)"))?;

        // public input: commit_root_t
        let commit_root_t = num::AllocatedNum::alloc(cs.namespace(|| "commit_root_t"), || {
            Ok(self.commit_root_t.unwrap())
        })?;
        commit_root_t.inputize(cs.namespace(|| "commit_root_t(public)"))?;

        // private input: addreses 0~15
        let mut addresses = vec![];
        for (i, a) in self.addresses.into_iter().enumerate() {
            let addr =
                num::AllocatedNum::alloc(cs.namespace(|| format!("addresses {}", i)), || {
                    Ok(a.unwrap())
                })?;
            addresses.push(addr);
        }

        // private input: passphrase
        let passphrase = num::AllocatedNum::alloc(cs.namespace(|| "passphrase"), || {
            Ok(self.passphrase.unwrap())
        })?;

        // private input: threshold
        let threshold =
            num::AllocatedNum::alloc(cs.namespace(|| "threshold"), || Ok(self.threshold.unwrap()))?;

        // public input: address_new
        let address_new = num::AllocatedNum::alloc(cs.namespace(|| "address_new"), || {
            Ok(self.address_new.unwrap())
        })?;
        address_new.inputize(cs.namespace(|| "address_new(public)"))?;

        // public input: nonce
        let nonce = num::AllocatedNum::alloc(cs.namespace(|| "nonce"), || Ok(self.nonce.unwrap()))?;
        nonce.inputize(cs.namespace(|| "nonce(public)"))?;

        // construct address root
        let address_root =
            bulid_merkle_tree(cs.namespace(|| "address merkle"), &addresses, self.params)?;

        // check cr and cr_t
        let mut t = combine_hash(
            cs.namespace(|| "hash(address_root,pass)"),
            NoteCommitment, &address_root, &passphrase, self.params
        )?;
        t = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &threshold, self.params
        )?;
        let computed_commit_root = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &nonce, self.params
        )?;
        let computed_commit_root_t = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &address_new, self.params,
        )?;

        cs.enforce(
            || "commit_root equality",
            |lc| lc + commit_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + computed_commit_root.get_variable(),
        );
        cs.enforce(
            || "commit_root_t equality",
            |lc| lc + commit_root_t.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + computed_commit_root_t.get_variable(),
        );

        Ok(())
    }
}

fn get_verification_from_parts<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    pre_transfer_index: &num::AllocatedNum<E>,
    sender_address: &num::AllocatedNum<E>,
    nonce1: &num::AllocatedNum<E>,
    nonce2: &num::AllocatedNum<E>,
    params: &E::Params
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let mut t = combine_hash(
        cs.namespace(|| "hash(txid, nonce1)"),
        NoteCommitment, &pre_transfer_index, &nonce1, params
    )?;
    t = combine_hash(
        cs.namespace(|| "hash(_, sender_addr)"),
        NoteCommitment, &t, &sender_address, params
    )?;
    Ok(combine_hash(
        cs.namespace(|| "hash(_, nonce2)"), NoteCommitment, &t, &nonce2, params
    )?)
}

fn inputize_allocated_bit<E: JubjubEngine, CS: ConstraintSystem<E>>(mut cs: CS, var :&boolean::AllocatedBit) -> Result<(), SynthesisError>{
    let input = cs.alloc_input(
        || "input variable",
        || match var.get_value().unwrap() {
            true => Ok(E::Fr::one()),
            false => Ok(E::Fr::zero())
        }
    )?;

    cs.enforce(
        || "enforce input is correct",
        |lc| lc + input,
        |lc| lc + CS::one(),
        |lc| lc + var.get_variable()
    );

    Ok(())
}

fn fr_eq<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS, a: &num::AllocatedNum<E>, b: &num::AllocatedNum<E>
) -> Result<boolean::Boolean, SynthesisError> {
    let a = a.into_bits_le(cs.namespace(|| "a into bits"))?;
    let b = b.into_bits_le(cs.namespace(|| "b into bits"))?;
    let mut result = boolean::Boolean::constant(true);
    for (i, (x, y)) in a.into_iter().zip(b.into_iter()).enumerate() {
        let s = boolean::Boolean::xor(cs.namespace(|| format!("xor bit {}", i)), &x, &y)?.not();
        result = boolean::Boolean::and(cs.namespace(|| format!("and bit {}", i)), &result, &s)?;
    }
    Ok(result)
}

impl<'a, E: JubjubEngine> Circuit<E> for PreparationCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // public input: commit_root
        let commit_root = num::AllocatedNum::alloc(cs.namespace(|| "commit_root"), || {
            Ok(self.commit_root.unwrap())
        })?;
        commit_root.inputize(cs.namespace(|| "commit_root(public)"))?;

        // private input: friend_address
        let friend_address = num::AllocatedNum::alloc(cs.namespace(|| "friend address"), || {
            Ok(self.friend_address.unwrap())
        })?;

        // private input: friend path
        let friend_path: Vec<num::AllocatedNum<E>> = self.friend_path
            .into_iter().enumerate()
            .map(|(i, x)| num::AllocatedNum::alloc(
                    cs.namespace(|| format!("friend paht {}", i)),
                    || Ok(x.unwrap())
                ).unwrap()
            ).collect();

        // public input: friend directions
        let mut friend_directions = vec![];
        for (i, x) in self.friend_directions.into_iter().enumerate() {
            let bit = boolean::AllocatedBit::alloc(
                    cs.namespace(|| format!("friend direction {}", i)), *x
            )?;
            inputize_allocated_bit(
                cs.namespace(|| format!("friend direction {} (public)", i)),
                &bit
            )?;
            friend_directions.push(boolean::Boolean::from(bit));
        }

        // private input: passphrase
        let passphrase = num::AllocatedNum::alloc(cs.namespace(|| "passphrase"), || {
            Ok(self.passphrase.unwrap())
        })?;

        // private input: threshold
        let threshold =
            num::AllocatedNum::alloc(cs.namespace(|| "threshold"), || Ok(self.threshold.unwrap()))?;
        
        // public input: nonce
        let nonce = num::AllocatedNum::alloc(cs.namespace(|| "nonce"), || Ok(self.nonce.unwrap()))?;
        nonce.inputize(cs.namespace(|| "nonce(public)"))?;

        // private input: verification
        let verification = num::AllocatedNum::alloc(cs.namespace(|| "verification"), || {
            Ok(self.verification.unwrap())
        })?;

        // public input: pre_transfer_index
        let pre_transfer_index = num::AllocatedNum::alloc(cs.namespace(|| "pre_transfer_index"), || {
            Ok(self.pre_transfer_index.unwrap())
        })?;
        pre_transfer_index.inputize(cs.namespace(|| "pre_transfer_index(public)"))?;

        // private input: verification_nonce1
        let verification_nonce1 = num::AllocatedNum::alloc(cs.namespace(|| "verification_nonce1"), || Ok(self.verification_nonce1.unwrap()))?;

        // private input: verification_nonce2
        let verification_nonce2 = num::AllocatedNum::alloc(cs.namespace(|| "verification_nonce2"), || Ok(self.verification_nonce2.unwrap()))?;

        // public input: verification_root
        let verification_root = num::AllocatedNum::alloc(
            cs.namespace(|| "verification_root"), || Ok(self.verification_root.unwrap())
        )?;
        verification_root.inputize(cs.namespace(|| "verification_root(public)"))?;

        // private input: verification path
        let verification_path: Vec<num::AllocatedNum<E>> = self.verification_path
            .into_iter().enumerate()
            .map(|(i, x)| num::AllocatedNum::alloc(
                    cs.namespace(|| format!("verification path {}", i)),
                    || Ok(x.unwrap())
                ).unwrap()
            ).collect();

        // public input: verification directions
        let verification_directions: Vec<boolean::Boolean> = self.verification_directions
            .into_iter().enumerate()
            .map(|(i, x)| {
                boolean::Boolean::from(
                    boolean::AllocatedBit::alloc(
                        cs.namespace(|| format!("friend direction {}", i)), *x
                    ).unwrap()
                )
            }).collect();

        // check the friend lies with commit_root with the right index
        let address_root = merkle_root_from_path(
            cs.namespace(|| "addr root"),
            &friend_address,
            &friend_path.into_iter().zip(friend_directions.into_iter()).collect::<Vec<(num::AllocatedNum<E>, boolean::Boolean)>>(),
            self.params
        )?;
        let mut t = combine_hash(
            cs.namespace(|| "hash(address_root,pass)"),
            NoteCommitment, &address_root, &passphrase, self.params
        )?;
        t = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &threshold, self.params
        )?;
        let computed_commit_root = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &nonce, self.params
        )?;
        cs.enforce(
            || "commit_root equality",
            |lc| lc + commit_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + computed_commit_root.get_variable(),
        );

        // check if friend_addr all zero
        let zero = num::AllocatedNum::alloc(
            cs.namespace(|| "alloc zero"),
            || Ok(E::Fr::zero())
        )?;
        let addr_nonzero = fr_eq(
            cs.namespace(|| "check zero addr"), 
            &friend_address, &zero)?.not();

        // check verification
        let computed_verification = get_verification_from_parts(
            cs.namespace(|| "compute verification"), 
            &pre_transfer_index,
            &friend_address,
            &verification_nonce1,
            &verification_nonce2,
            self.params
        )?;
        let verification_eq = fr_eq(
            cs.namespace(|| "verification equality"),
            &computed_verification, &verification,
        )?;

        // check verification existence
        let computed_verification_root = merkle_root_from_path(
            cs.namespace(|| "compute verification root"),
            &verification,
            &verification_path.into_iter()
            .zip(verification_directions.into_iter())
            .collect::<Vec<(num::AllocatedNum<E>, boolean::Boolean)>>(),
            self.params
        )?;
        let verification_exists = fr_eq(
            cs.namespace(|| "verification exists") , 
            &computed_verification_root,
            &verification_root
        )?;

        let verification_check_fails = boolean::Boolean::and(
            cs.namespace(|| "verification valid and exists"),
            &verification_eq,
            &verification_exists
        )?.not();

        let fails = boolean::Boolean::and(
            cs.namespace(|| "addr non-zero and verification check failed"),
            &addr_nonzero,
            &verification_check_fails,
        )?;

        // shouldn't fail
        boolean::Boolean::enforce_equal(
            cs.namespace(|| "shouldn't fail"),
            &fails,
            &boolean::Boolean::constant(false)
        )?;

        Ok(())
    }
}

fn count_valid_addreses<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    addreses: &[num::AllocatedNum<E>],
    vlist: &[boolean::Boolean],
) -> Result<num::AllocatedNum<E>, SynthesisError> {
    let zero = num::AllocatedNum::alloc(
        cs.namespace(|| "alloc zero"),
        || Ok(E::Fr::zero())
    )?;
    let is_addr_not_null: Vec<boolean::Boolean> = addreses
        .into_iter().enumerate().map(
            |(i, a)| 
            fr_eq(cs.namespace(|| format!("check null address {}", i)), a, &zero).unwrap().not()
        ).collect();
    let is_addr_valid: Vec<boolean::Boolean> = vlist
        .into_iter().zip(is_addr_not_null.into_iter()).enumerate().map(
            |(i, (v, a))| boolean::Boolean::and(
                cs.namespace(|| format!("check valid address {}", i)), 
                &v, &a
            ).unwrap()
        ).collect();
    let result = num::AllocatedNum::alloc(
        cs.namespace(|| "alloc valid address count"),
        || {
            let mut r = 0;
            for b in &is_addr_valid {
                if b.get_value().unwrap() == true {
                    r += 1;
                }
            }
            Ok(E::Fr::from_str(&r.to_string()).unwrap())
        })?;
    let mut result_lc = bellman::LinearCombination::<E>::zero();
    for (i, b) in is_addr_valid.into_iter().enumerate() {
        let bit = boolean::AllocatedBit::alloc(
            cs.namespace(|| format!("valid bit {}", i)),
            b.get_value()
        )?;

        result_lc = result_lc + bit.get_variable();

        let bit_boolean = boolean::Boolean::from(bit);
        boolean::Boolean::enforce_equal(
            cs.namespace(|| format!("valid bit eq {}", i)),
            &bit_boolean, &b
        )?;

    }
    // constraint result
    cs.enforce(
        || "enforce result",
        |_| result_lc,
        |lc| lc + CS::one(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

fn check_address_cnt<E: JubjubEngine, CS: ConstraintSystem<E>> (
    mut cs: CS,
    address_cnt: &num::AllocatedNum<E>,
    threshold: &num::AllocatedNum<E>,
) -> Result<boolean::Boolean, SynthesisError> {
    let mut aboves = vec![];
    for i in 0..16 {
        let n = num::AllocatedNum::alloc(
            cs.namespace(|| format!("threshold+{}", i)),
            || {
                let mut t: E::Fr = threshold.get_value().unwrap().clone();
                t.add_assign(&E::Fr::from_str(&i.to_string()).unwrap());
                Ok(t)
            }
        )?;
        cs.enforce(
            || format!("constraint threshold-{}", i),
            |lc| lc+threshold.get_variable()+(E::Fr::from_str(&i.to_string()).unwrap(), CS::one()),
            |lc| lc+CS::one(),
            |lc| lc+n.get_variable(),
        );
        aboves.push(n);
    }
    let not_eqs: Vec<boolean::Boolean> = aboves.into_iter().enumerate().map(
        |(i, n)| 
            fr_eq(
                cs.namespace(|| format!("check below eq {}", i)), &address_cnt, &n
            ).unwrap().not()
    ).collect();
    let mut all_not_eq = boolean::Boolean::constant(true);
    for (i, neq) in not_eqs.into_iter().enumerate() {
        all_not_eq = boolean::Boolean::and(
            cs.namespace(|| format!("and not_qe {}", i)),
            &neq, &all_not_eq
        )?;
    }
    Ok(all_not_eq.not())
}

impl<'a, E: JubjubEngine> Circuit<E> for TransferCircuit<'a, E> {
    fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        // public input: commit_root
        let commit_root = num::AllocatedNum::alloc(cs.namespace(|| "commit_root"), || {
            Ok(self.commit_root.unwrap())
        })?;
        commit_root.inputize(cs.namespace(|| "commit_root(public)"))?;

        // public input: vlist
        let mut vlist = vec![];
        for (i, a) in self.vlist.into_iter().enumerate() {
            let vbit = boolean::AllocatedBit::alloc(
                cs.namespace(|| format!("vlist bit {}", i)),
                *a
            )?;
            inputize_allocated_bit(
                cs.namespace(|| format!("vlist bit {}(public)", i)), &vbit
            )?;
            vlist.push(boolean::Boolean::from(vbit));
        }

        // private input: addreses 0~15
        let addresses: Vec<num::AllocatedNum<E>> = self.addresses.into_iter()
        .enumerate().map(
            |(i, a)| 
                num::AllocatedNum::alloc(cs.namespace(|| format!("addresses {}", i)), || {
                    Ok(a.unwrap())
                }).unwrap()
        ).collect();

        // private input: passphrase
        let passphrase = num::AllocatedNum::alloc(cs.namespace(|| "passphrase"), || {
            Ok(self.passphrase.unwrap())
        })?;

        // private input: threshold
        let threshold =
            num::AllocatedNum::alloc(cs.namespace(|| "threshold"), || Ok(self.threshold.unwrap()))?;

        // private input: nonce
        let nonce = num::AllocatedNum::alloc(cs.namespace(|| "nonce"), || Ok(self.nonce.unwrap()))?;

        // construct address root
        let address_root =
            bulid_merkle_tree(cs.namespace(|| "address merkle"), &addresses, self.params)?;

        // check commit root
        let mut t = combine_hash(
            cs.namespace(|| "hash(address_root,pass)"),
            NoteCommitment, &address_root, &passphrase, self.params
        )?;
        t = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &threshold, self.params
        )?;
        let computed_commit_root = combine_hash(
            cs.namespace(|| "hash(_, threshold)"),
            NoteCommitment, &t, &nonce, self.params
        )?;
        cs.enforce(
            || "commit_root equality",
            |lc| lc + commit_root.get_variable(),
            |lc| lc + CS::one(),
            |lc| lc + computed_commit_root.get_variable(),
        );


        let valid_addr_cnt = count_valid_addreses(
            cs.namespace(|| "count addresses"), 
            &addresses, &vlist
        )?;

        let enough_valid_addr = check_address_cnt(
            cs.namespace(|| "check address cnt"), 
            &valid_addr_cnt, &threshold
        )?;

        boolean::Boolean::enforce_equal(
            cs.namespace(|| "valid address cnt should be enough"),
            &enough_valid_addr, &boolean::Boolean::constant(true)
        )?;

        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use bellman::groth16::*;
    use bellman::{Circuit, ConstraintSystem, SynthesisError};
    use ff::{BitIterator, PrimeField};
    use pairing::bls12_381::*;
    use rand::{Rng, SeedableRng, XorShiftRng};
    use sapling_crypto::circuit::{boolean, num};
    use sapling_crypto::{jubjub::*, pedersen_hash};

    fn fr_to_bits_le<E: JubjubEngine>(x: &E::Fr) -> Vec<bool> {
        BitIterator::new(x.into_repr())
            .collect::<Vec<bool>>()
            .into_iter()
            .rev()
            .take(E::Fr::NUM_BITS as usize)
            .collect()
    }

    fn combine_hash(personalization: pedersen_hash::Personalization, a: &Fr, b: &Fr, params: &JubjubBls12) -> Fr {
        pedersen_hash::pedersen_hash::<Bls12, _>(
            personalization,
            fr_to_bits_le::<Bls12>(a).into_iter().chain(
                        fr_to_bits_le::<Bls12>(b).into_iter()),
            params
        ).into_xy().0
    }

    #[test]
    fn test_pre_transfer_circuit() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let friends = vec![Fr::from_str("0").unwrap(); super::MAX_FRIENDS_LEN];
        let threshold = Fr::from_str("111111").unwrap();
        let passphrase = Fr::from_str("222222").unwrap();
        let nonce = Fr::from_str("333333").unwrap();
        let addr_new = Fr::from_str("444444").unwrap();

        let mut cur = friends.clone();
        let mut level = 0;
        while cur.len() > 1 {
            let prev = cur;
            cur = vec![];
            for i in 0..prev.len()/2 {
                let (xl, xr) = (prev[2*i], prev[2*i+1]);
                let digest = combine_hash(
                    pedersen_hash::Personalization::MerkleTree(level), 
                    &xl, &xr,
                    &params
                );
                cur.push(digest);
            }
            level += 1;
        }

        let addr_root = cur[0];
        let mut t = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &addr_root,
            &passphrase,
            &params);
        t = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &t,
            &threshold,
            &params);
        
        let commit_root = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &t,
            &nonce,
            &params);
        let commit_root_t = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &t,
            &addr_new,
            &params);

        let zk_params = {
            let instance = super::PreTransferCircuit::<Bls12> {
                commit_root: None,
                commit_root_t: None,
                addresses: &vec![None; super::MAX_FRIENDS_LEN],
                passphrase: None,
                threshold: None,
                address_new: None,
                nonce: None,
                params: &params,
            };
            generate_random_parameters(instance, rng).unwrap()
        };
        
        let instance = super::PreTransferCircuit::<Bls12> {
            commit_root: Some(commit_root),
            commit_root_t: Some(commit_root_t),
            addresses: &friends.into_iter().map(|x| Some(x)).collect::<Vec<Option<Fr>>>(),
            passphrase: Some(passphrase),
            threshold: Some(threshold),
            address_new: Some(addr_new),
            nonce: Some(nonce),
            params: &params,
        };
        let proof = create_random_proof(instance, &zk_params, rng).unwrap();
        let pvk = prepare_verifying_key(&zk_params.vk);
        assert!(verify_proof(&pvk, &proof, &vec![commit_root, commit_root_t, addr_new, nonce]).unwrap());
    }

    #[test]
    fn test_transfer_circuit() {
        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);

        let friends: Vec<Fr> = vec![0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0].into_iter().map(|x| Fr::from_str(&x.to_string()).unwrap()).collect();
        let threshold = Fr::from_str("2").unwrap();
        let passphrase = Fr::from_str("222222").unwrap();
        let nonce = Fr::from_str("333333").unwrap();
        let vlist = vec![1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let vlist_bool: Vec<Option<bool>> = (&vlist).into_iter().map(
            |x| Some(
                match x {
                    0 => false,
                    _ => true
                }
            )
        ).collect();

        let mut cur = friends.clone();
        let mut level = 0;
        while cur.len() > 1 {
            let prev = cur;
            cur = vec![];
            for i in 0..prev.len()/2 {
                let (xl, xr) = (prev[2*i], prev[2*i+1]);
                let digest = combine_hash(
                    pedersen_hash::Personalization::MerkleTree(level), 
                    &xl, &xr,
                    &params
                );
                cur.push(digest);
            }
            level += 1;
        }

        let addr_root = cur[0];
        let mut t = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &addr_root,
            &passphrase,
            &params);
        t = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &t,
            &threshold,
            &params);
        
        let commit_root = combine_hash(
            pedersen_hash::Personalization::NoteCommitment,
            &t,
            &nonce,
            &params);

        let zk_params = {
            let instance = super::TransferCircuit::<Bls12> {
                commit_root: None,
                vlist: &vec![None; super::MAX_FRIENDS_LEN],
                addresses: &vec![None; super::MAX_FRIENDS_LEN],
                passphrase: None,
                threshold: None,
                nonce: None,
                params: &params,
            };
            generate_random_parameters(instance, rng).unwrap()
        };
        
        let instance = super::TransferCircuit::<Bls12> {
            commit_root: Some(commit_root),
            vlist: &vlist_bool,
            addresses: &friends.into_iter().map(|x| Some(x)).collect::<Vec<Option<Fr>>>(),
            passphrase: Some(passphrase),
            threshold: Some(threshold),
            nonce: Some(nonce),
            params: &params,
        };
        let proof = create_random_proof(instance, &zk_params, rng).unwrap();
        let pvk = prepare_verifying_key(&zk_params.vk);
        let mut inputs = vec![];
        inputs.push(commit_root);
        inputs.extend(vlist.into_iter().map(|x| Fr::from_str(&x.to_string()).unwrap()).collect::<Vec<Fr>>());
        assert!(verify_proof(&pvk, &proof, &inputs).unwrap());
    }

    #[test]
    fn test_merkle_root_from_path() {
        struct MerkleRootFromPathCircuit<'a, E: JubjubEngine> {
            leaf: Option<E::Fr>,
            auth_path: &'a [Option<(E::Fr, bool)>],
            params: &'a E::Params,
            merkle_root: Option<E::Fr>,
        }

        impl<'a, E: JubjubEngine> Circuit<E> for MerkleRootFromPathCircuit<'a, E> {
            fn synthesize<CS: ConstraintSystem<E>>(
                self,
                cs: &mut CS,
            ) -> Result<(), SynthesisError> {
                let leaf = num::AllocatedNum::alloc(cs.namespace(|| "merkle leaf"), || {
                    Ok(self.leaf.unwrap())
                })?;
                let mut auth_path = vec![];
                for (i, p) in self.auth_path.into_iter().enumerate() {
                    let digest = num::AllocatedNum::alloc(
                        cs.namespace(|| format!("path digest {}", i)),
                        || Ok(p.unwrap().0),
                    )?;
                    let direction = boolean::Boolean::from(boolean::AllocatedBit::alloc(
                        cs.namespace(|| format!("path direction {}", i)),
                        p.map(|x| x.1),
                    )?);
                    auth_path.push((digest, direction));
                }
                let hash_result = super::merkle_root_from_path(
                    cs.namespace(|| "root from path"),
                    &leaf,
                    &auth_path,
                    &self.params,
                )?;
                let merkle_root = num::AllocatedNum::alloc(cs.namespace(|| "merkle root"), || {
                    Ok(self.merkle_root.unwrap())
                })?;
                merkle_root.inputize(cs.namespace(|| "merkle root input"))?;
                cs.enforce(
                    || "merkle root equality",
                    |lc| lc + hash_result.get_variable(),
                    |lc| lc + CS::one(),
                    |lc| lc + merkle_root.get_variable(),
                );
                Ok(())
            }
        }

        let params = &JubjubBls12::new();
        let rng = &mut XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let tree_depth = 5;
        let auth_path = vec![Some((rng.gen(), rng.gen())); tree_depth];

        let leaf: Fr = rng.gen();
        let mut cur = leaf.clone();
        for (i, val) in auth_path.clone().into_iter().enumerate() {
            let (uncle, b) = val.unwrap();
            let mut lhs = cur;
            let mut rhs = uncle;
            if b {
                ::std::mem::swap(&mut lhs, &mut rhs);
            }
            cur = pedersen_hash::pedersen_hash::<Bls12, _>(
                pedersen_hash::Personalization::MerkleTree(i),
                fr_to_bits_le::<Bls12>(&lhs)
                    .into_iter()
                    .chain(fr_to_bits_le::<Bls12>(&rhs).into_iter()),
                params,
            )
            .into_xy()
            .0;
        }

        let zk_params = {
            let instance = MerkleRootFromPathCircuit::<Bls12> {
                leaf: None,
                auth_path: &vec![None; tree_depth],
                merkle_root: None,
                params: &params,
            };
            generate_random_parameters(instance, rng).unwrap()
        };

        let pvk = prepare_verifying_key(&zk_params.vk);
        let instance = MerkleRootFromPathCircuit::<Bls12> {
            leaf: Some(leaf),
            auth_path: &auth_path,
            merkle_root: Some(cur),
            params: &params,
        };
        let proof = create_random_proof(instance, &zk_params, rng).unwrap();
        assert!(verify_proof(&pvk, &proof, &vec![cur.clone()]).unwrap());
    }
}
