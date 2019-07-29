pragma solidity >=0.4.22 <0.6.0;
pragma experimental ABIEncoderV2;

contract ZkRevert {
    // Constants

    uint constant MAX_FRIENDS_LEN = 16;
    uint constant VERIFICATION_MERKLE_DEPTH = 32;
    uint constant BLOCK_DELAY = 6;

    uint constant ZK_PRETRANSFER = 0;
    uint constant ZK_PREPARATION = 1;
    uint constant ZK_TRANSFER = 2;


    // Types

    struct CommitTx {
        address sender;
        bytes32 commit_root;
        uint256 limit;
        bytes32 nonce;
    }

    struct PreTransferTx {
        address sender;
        uint commit_index;
        bytes verified;  // binary array
        uint block_num;
    }

    struct VerificationTx {
        address sender;
        bytes32 verification;
        bytes32 pre_transfer_commitment;
        bytes32 nonce;
    }


    // Events

    event CommitTxEvent(uint commit_index, string notes);
    event InvalidateTxEvent(uint commit_index);
    event PreTransferTxEvent(uint indexed commit_index, uint pre_transfer_index);
    event InvitationEvent(bytes invitation);
    event VerificationTxEvent(uint verification_index, bytes verification_receipt);
    event TransferEvent(uint amount);


    // States
    bool skip_zk;  // if set, all zk checks will be ignored

    CommitTx[] public commits;
    mapping (uint => bool) public used_commits;

    PreTransferTx[] public pre_transfers;

    VerificationTx[] public verifications;
    bytes32[][VERIFICATION_MERKLE_DEPTH] verification_merkle;
    mapping (bytes32 => bool) public verification_root_history;

    bytes32 null_verification_digest;
    bytes32[VERIFICATION_MERKLE_DEPTH] null_merkle_path;


    // Functions

    constructor(bool _skip_zk) public {
        // initialize null values in verification merkle
        null_verification_digest = bytes32(0x0);
        bytes32 prev_digest = null_verification_digest;
        for (uint i = 0; i < VERIFICATION_MERKLE_DEPTH; i++) {
            uint curr_level = VERIFICATION_MERKLE_DEPTH-i-1;
            null_merkle_path[curr_level] = _hash_two_bytes32(prev_digest, prev_digest, (int)(i));
            prev_digest = null_merkle_path[curr_level];
        }

        skip_zk = _skip_zk;
    }

    function _bytes_to_bytes32(bytes b, uint offset) private pure returns (bytes32 out) {
        for (uint i = 0; i < 32; i++) {
            out |= bytes32(b[offset + i] & 0xff) >> (i * 8);
        }
    }

    function _address_to_bytes32(address addr) private pure returns (bytes32) {
        bytes memory _result = new bytes(32);
        uint addr_uint = uint(addr);
        for (uint i = 0; i < 20; i++) {
            _result[i] = byte(uint8(addr_uint / (2**(8*(19 - i)))));
        }
        return _bytes_to_bytes32(_result, 0);
    }

    function _address_to_bytes(address addr) private pure returns (bytes out) {
        out = new bytes(20);
        uint addr_uint = uint(addr);
        for (uint i = 0; i < 20; i++) {
            out[i] = byte(uint8(addr_uint / (2**(8*(19 - i)))));
        }
    }

    function _uint_to_bytes(uint256 x) private pure returns (bytes out) {
        out = new bytes(32);
        assembly { mstore(add(out, 32), x) }
    }

    function _int_to_bytes(int256 x) private pure returns (bytes out) {
        out = new bytes(32);
        assembly { mstore(add(out, 32), x) }
    }
    
    function commit_tx(
        bytes32 _commit_root,
        uint _limit,
        bytes32 _nonce,
        string notes
    ) public {
        commits.push(CommitTx({
            sender: msg.sender,
            commit_root: _commit_root,
            limit: _limit,
            nonce: _nonce
        }));
        
        emit CommitTxEvent(commits.length-1, notes);
    }

    function _get_unused_commit_tx(uint index) private view returns (CommitTx storage) {
        require(
            index < commits.length && !used_commits[index],
            "invalid index"
        );
        return commits[index];
    }

    function invalidate_tx(uint commit_index) public {
        require(
            _get_unused_commit_tx(commit_index).sender == msg.sender,
            "permission denied"
        );
        used_commits[commit_index] = true;
    }

    function _zk_verify(bytes input) private returns (uint) {
        if (skip_zk) {
            return 1;
        }

        uint256[1] memory output;
        uint length = input.length;
        assembly {
            // call verify_verification precompile
            if iszero(call(not(0), 0x9, 0, add(input, 0x20), length, output, 0x20)) {
                revert(0, 0)
            }
        }
        return output[0]; 
    }

    function _zk_verify_pre_transfer(
        bytes32 commit_root, 
        bytes32 commit_root_t, 
        bytes32 addr_padded, 
        bytes32 nonce,
        bytes proof
    ) private returns (uint) {
        // TODO: delete this line
        // return 1;

        uint input_length = 32 * 4;            
        uint total_length = 64 + input_length + proof.length;
        bytes memory input = new bytes(total_length);

        _copy_bytes(input, _uint_to_bytes(ZK_PRETRANSFER),0x00);
        _copy_bytes(input, _uint_to_bytes(input_length), 0x20);
        _copy_bytes32(input, commit_root, 0x40+0x00);
        _copy_bytes32(input, commit_root_t, 0x40+0x20);
        _copy_bytes32(input, addr_padded, 0x40+0x40);
        _copy_bytes32(input, nonce, 0x40+0x60);
        _copy_bytes(input, proof, 0x40+0x80);
        return _zk_verify(input);
    }

    function pre_transfer_tx(
        uint _commit_index,
        bytes32 commit_root_t,
        bytes pre_transfer_proof,
        bytes[MAX_FRIENDS_LEN] memory _invitations
    ) public {
        CommitTx storage commit = _get_unused_commit_tx(_commit_index);
        bytes32 addr_padded = _address_to_bytes32(msg.sender);
        require(
            _zk_verify_pre_transfer(
                commit.commit_root, 
                commit_root_t,
                addr_padded, 
                commit.nonce,
                pre_transfer_proof) == 1,
            "invalid proof"
        );

        pre_transfers.push(PreTransferTx({
            commit_index: _commit_index,
            sender: msg.sender,
            verified: new bytes(MAX_FRIENDS_LEN),
            block_num: block.number
        }));
        emit PreTransferTxEvent(_commit_index, pre_transfers.length-1);
        for (uint i = 0; i < MAX_FRIENDS_LEN; i++) {
            emit InvitationEvent(_invitations[i]);
        }
    }

    function _get_pre_transfer_tx(uint index) private view returns (PreTransferTx storage) {
        require(
            index < pre_transfers.length,
            "invalid pre_transfer tx"
        );
        return pre_transfers[index];
    }

    function _get_unused_commit_by_pre_transfer(uint index) private view returns (CommitTx storage) {
        PreTransferTx storage pre_transfer = _get_pre_transfer_tx(index);
        return _get_unused_commit_tx(pre_transfer.commit_index);
    }

    function _copy_bytes(bytes dst, bytes src, uint start_index) private pure {
        for (uint i = 0; i < src.length; i++) {
            dst[start_index+i] = src[i];
        }
    }

    function _copy_bytes32(bytes dst, bytes32 src, uint start_index) private pure {
        for (uint i = 0; i < 32; i++) {
            dst[start_index+i] = src[i];
        }
    }

    function _hash_two_bytes32(
        bytes32 lhs,
        bytes32 rhs,
        int256 personalization // -1 for commitment, >=0 for merkel hash
    ) private returns (bytes32) {
        bytes32[1] memory results;
        bytes memory combined = new bytes(0x60);
        _copy_bytes(combined, _int_to_bytes(personalization), 0);
        _copy_bytes32(combined, lhs, 0x20);
        _copy_bytes32(combined, rhs, 0x40);
        assembly {
            // call jubjubhash
            if iszero(call(not(0), 0xb, 0, add(combined, 0x20), 0x60, results, 0x20)) {
                revert(0, 0)
            }
        }
        return results[0];
    }

    function _get_verification_merkle_digest(uint level, uint index) private view returns (bytes32 digest) {
        require(
            level <= VERIFICATION_MERKLE_DEPTH,
            "invalid level"
        );

        // get verification digest
        if (level == VERIFICATION_MERKLE_DEPTH) {
            if (index >= verifications.length) {
                return digest = null_verification_digest;
            } else {
                return digest = verifications[index].verification;
            }
        }

        if (index >= verification_merkle[level].length) {
            digest = null_merkle_path[level];
        } else {
            digest = verification_merkle[level][index];
        }
    }

    function _write_verification_merkle_digest(uint level, uint index, bytes32 digest) private {
        require(
            level < VERIFICATION_MERKLE_DEPTH, // can't write verification digest
            "invalid level"
        );
        require(
            index <= verification_merkle[level].length, // update or append 1 new digest
            "invalid digest"
        );

        if (index == verification_merkle[level].length) { // append
            verification_merkle[level].push(digest);
        } else {  // update
            verification_merkle[level][index] = digest;
        }
    }

    function _update_verification_merkle(uint index) private {
        for (uint i = 0; i < VERIFICATION_MERKLE_DEPTH; i++) {
            uint parent_index = index >> (i+1);
            uint curr_level = VERIFICATION_MERKLE_DEPTH-i;
            bytes32 lhs = _get_verification_merkle_digest(curr_level, parent_index*2);
            bytes32 rhs = _get_verification_merkle_digest(curr_level, parent_index*2+1);
            _write_verification_merkle_digest(curr_level-1, parent_index, _hash_two_bytes32(lhs, rhs, (int)(i)));
        }
    }

    function _verify_verification(
        bytes32 verification, 
        bytes32 addr_padded, 
        bytes32 pre_transfer_commitment,
        bytes32 nonce
    ) private {
        bytes32 t = _hash_two_bytes32(pre_transfer_commitment, addr_padded, -1);
        require(
            verification == _hash_two_bytes32(t, nonce, -1),
            "verification and address don't match"
        );
    }

    function verification_tx(
        bytes32 _verification,
        bytes32 _pre_transfer_commitment,
        bytes32 _nonce,
        bytes verification_receipt
    ) public {
        bytes32 addr_padded = _address_to_bytes32(msg.sender);
        _verify_verification(
            _verification, 
            addr_padded,
            _pre_transfer_commitment, 
            _nonce
        );

        verifications.push(VerificationTx({
            sender: msg.sender,
            verification: _verification,
            pre_transfer_commitment: _pre_transfer_commitment,
            nonce: _nonce
        }));
        _update_verification_merkle(verifications.length-1);
        verification_root_history[verification_merkle[0][0]] = true;
        emit VerificationTxEvent(verifications.length-1, verification_receipt);
    }

    function get_verification_path_proof(uint verification_index) public view returns (
        bytes32 root, 
        uint[VERIFICATION_MERKLE_DEPTH] directions, 
        bytes32[VERIFICATION_MERKLE_DEPTH] path, 
        bytes32 verification_digest
    ) {
        require(
            verification_index < verifications.length,
            "invalid index"
        );

        root = _get_verification_merkle_digest(0, 0);
        verification_digest = _get_verification_merkle_digest(VERIFICATION_MERKLE_DEPTH, verification_index);

        for (uint i = 0; i < VERIFICATION_MERKLE_DEPTH; i++) {
            uint level_index = verification_index >> i;
            uint curr_level = VERIFICATION_MERKLE_DEPTH-i;
            directions[i] = level_index & 0x1;
            if (directions[i] == 1) {
                path[i] = _get_verification_merkle_digest(curr_level, level_index-1);
            } else {
                path[i] = _get_verification_merkle_digest(curr_level, level_index+1);
            }
        }
    }

    function _verify_preparation(
        bytes32 commit_root,
        uint friend_index,
        bytes32 nonce,
        uint pre_transfer_index,
        bytes32 verification_root,
        bytes proof
    ) private returns (uint) {
        // TODO: delete this line
        // return 1;
        
        uint input_length = 32*5;
        uint total_length = 64 + input_length + proof.length;
        bytes memory input = new bytes(total_length);

        _copy_bytes(input, _uint_to_bytes(ZK_PREPARATION),0x00);
        _copy_bytes(input, _uint_to_bytes(input_length), 0x20);
        _copy_bytes32(input, commit_root, 0x40+0x00);
        _copy_bytes(input, _uint_to_bytes(friend_index), 0x40+0x20);
        _copy_bytes32(input, nonce, 0x40+0x40);
        _copy_bytes(input, _uint_to_bytes(pre_transfer_index), 0x40+0x60);
        _copy_bytes32(input, verification_root, 0x40+0x80);
        _copy_bytes(input, proof, 0x40+0xa0);
        return _zk_verify(input);
    }

    function preparation_tx(
        uint pre_transfer_index,
        uint friend_index,
        bytes32 verification_root,
        bytes preparation_proof
    ) public {
        PreTransferTx storage pre_transfer = _get_pre_transfer_tx(pre_transfer_index);
        require(
            verification_root_history[verification_root],
            "invalid verification_root"
        );
        require(
            pre_transfer.sender == msg.sender,
            "pre_transfer_sender doesn't match"
        );
        require(
            friend_index < MAX_FRIENDS_LEN && pre_transfer.verified[friend_index] == 0,
            "invalid friend_index"
        );
        CommitTx storage commit = _get_unused_commit_tx(pre_transfer.commit_index);
        require(
            _verify_preparation(
                commit.commit_root,
                friend_index, 
                commit.nonce, 
                pre_transfer_index,
                verification_root, 
                preparation_proof) == 1,
            "invalid proof"
        );
        pre_transfer.verified[friend_index] = (byte)(1);
    }

    function _verify_transfer(
        bytes32 commit_root,
        bytes verified,
        bytes proof
    ) private returns (uint) {
        // TODO: delete this line
        // return 1;
        uint input_length = 32 + 16;
        uint total_length = 64 + input_length + proof.length;
        bytes memory input = new bytes(total_length);

        _copy_bytes(input, _uint_to_bytes(ZK_TRANSFER),0x00);
        _copy_bytes(input, _uint_to_bytes(input_length), 0x20);
        _copy_bytes32(input, commit_root, 0x40+0x00);
        _copy_bytes(input, verified, 0x40+0x20);
        _copy_bytes(input, proof, 0x40+0x30);
        return _zk_verify(input);
    }

    function _transfer(address addr_old, uint limit) private returns (uint) {
        uint input_length = 20+32;
        bytes memory input = new bytes(input_length);
        uint[1] memory output;

        _copy_bytes(input, _address_to_bytes(addr_old), 0);
        _copy_bytes(input, _uint_to_bytes(limit), 20);

        assembly {
            // call verify_verification precompile
            if iszero(call(not(0), 0xa, 0, add(input, 0x20), input_length, output, 0x20)) {
                revert(0, 0)
            }
        }
        return output[0]; 
    }

    function dummy_tx() public {}

    function transfer_tx(
        uint pre_transfer_index,
        bytes transfer_proof
    ) public {
        PreTransferTx storage pre_transfer = _get_pre_transfer_tx(pre_transfer_index);
        require(
            msg.sender == pre_transfer.sender,
            "invalid sender"
        );
        CommitTx storage commit = _get_unused_commit_tx(pre_transfer.commit_index);
        require(
            _verify_transfer(commit.commit_root, pre_transfer.verified, transfer_proof) == 1,
            "invalid proof"
        );
        
        uint amount = _transfer(commit.sender, commit.limit);
        used_commits[pre_transfer.commit_index] = true;
        emit TransferEvent(amount);
    }
}
