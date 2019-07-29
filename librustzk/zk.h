#pragma once

void _jubjub_hash(
    int personalization, // -1 for commitment, >= 0 for merkle tree
    const char *fr_ptr_a, const char *fr_ptr_b, const char *out_ptr);

int _verify_pre_transfer_proof(const char *commit_root,
                               const char *commit_root_t,
                               const char *address_new, const char *nonce,
                               const char *proof, int proof_len, const char *vk,
                               int vk_len);

int _verify_preparation_proof(const char *commit_root,
                              const char *friend_directions, const char *nonce,
                              const char *pre_transfer_index,
                              const char *verification_root, const char *proof,
                              int proof_len, const char *vk, int vk_len);

int _verify_transfer_proof(const char *commit_root, const char *vlist,
                           const char *proof, int proof_len, const char *vk,
                           int vk_len);