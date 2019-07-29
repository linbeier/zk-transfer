from functools import reduce
from operator import add
import random
from os import urandom
from hashlib import sha256
from ctypes import (cdll, create_string_buffer, c_int, c_void_p, addressof)

import web3
from web3 import Web3
from web3.contract import ConciseContract
from constants import *
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key, keys


def timing(f):
    from functools import wraps
    from time import time

    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        print('\n====== func:%r took: %2.4f sec ======\n' %
              (f.__name__, te-ts))
        return result
    return wrap


class ZkTransfer:
    # Provides jubjubhash ans zk-related functions
    librustzk = cdll.LoadLibrary("librustzk.so")

    def __init__(self, contract_addr, contract_abi, w3, addr2key, zk_params_dir, skip_zk=False):
        self.skip_zk = skip_zk
        self.w3 = w3
        self.addr2key = addr2key
        self.contract = self.w3.eth.contract(
            address=Web3.toChecksumAddress(contract_addr), abi=contract_abi)

        # load zk-related keys
        self.load_zk_keys(zk_params_dir)

    @staticmethod
    def _sha256checksum(filename):
        import hashlib
        sha256_hash = hashlib.sha256()
        with open(filename, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def load_zk_keys(self, zk_params_dir):
        if zk_params_dir.endswith("/"):
            zk_params_dir = zk_params_dir[:-1]

        with open(zk_params_dir+"/pre-transfer.params", "rb") as fh:
            self.pre_transfer_params = fh.read()
        with open(zk_params_dir+"/preparation.params", "rb") as fh:
            self.preparation_params = fh.read()
        with open(zk_params_dir+"/transfer.params", "rb") as fh:
            self.transfer_params = fh.read()

    @staticmethod
    def _pad_bytes(data, length=HASH_BYTES, prepend=False):
        if len(data) > length:
            raise Exception("data overflows bytes{}".format(length))
        padding = b'\x00'*(length-len(data))
        return data+padding if not prepend else padding+data

    @staticmethod
    def _pad_int(data):
        return data.to_bytes(32, byteorder='little')

    @staticmethod
    def _pad_str(data):
        return ZkTransfer._pad_bytes(data.encode('utf-8'))

    @staticmethod
    def _pad_hexstr(data):
        return ZkTransfer._pad_bytes(Web3.toBytes(hexstr=data))

    @staticmethod
    def _to_cbuf(data):
        buffer = create_string_buffer(len(data))
        buffer.raw = data
        return buffer

    @staticmethod
    def _jubjubhash(x, y, t):
        buffer_x, buffer_y = ZkTransfer._to_cbuf(x), ZkTransfer._to_cbuf(y)
        out = create_string_buffer(HASH_BYTES)
        ZkTransfer.librustzk._jubjub_hash(c_int(t), buffer_x, buffer_y, out)
        return out.raw

    @staticmethod
    def _accumulate_hash(*args, t=-1):
        if not all(map(lambda x: isinstance(x, bytes) and len(x) == 32, args)):
            raise Exception("hashing non-bytes object")
        return reduce(lambda x, y:  ZkTransfer._jubjubhash(x, y, t), args)

    def _get_nonce(self):
        return urandom(NONCE_BYTES-1)+b'\x00'  # fit the bls12-381 Fr

    @staticmethod
    def _extend_friends(_friends, passphrase, threshold, nonce):
        friends_len = len(_friends)

        # check length/format and normalize
        if friends_len > MAX_FRIENDS_LEN:
            raise Exception("friends list too long")
        if not all(map(Web3.isAddress, _friends)):
            raise Exception("invalid address")
        friends = sorted(list(map(Web3.toChecksumAddress, _friends)))

        # init seed with friends[0]+...+frinds[n-1]+pass+threshold+nonce
        friends_bytes = [Web3.toBytes(hexstr=f) for f in friends]
        seed = sha256(reduce(add, friends_bytes) +
                      passphrase + threshold + nonce).digest()
        random.seed(seed)

        # genereate random indexes
        indexes = []
        while len(indexes) < friends_len:
            r = random.randrange(0, MAX_FRIENDS_LEN-1)
            while r in indexes:
                r = random.randrange(0, MAX_FRIENDS_LEN-1)
            indexes.append(r)

        result = [NULL_ADDRESS]*MAX_FRIENDS_LEN
        for i, r in enumerate(indexes):
            result[r] = friends[i]
        return result

    @staticmethod
    def _get_extended_friend_index(extended_friends, friends, friend_index):
        if friend_index < len(friends):
            return extended_friends.index(Web3.toChecksumAddress(friends[friend_index]))

        friend_index -= len(friends)
        for i, f in enumerate(extended_friends):
            if f != NULL_ADDRESS:
                continue
            if friend_index == 0:
                return i
            friend_index -= 1

    @staticmethod
    def _build_friends_merkle_tree(extended_friends):
        """ construct a merkle tree from a list of addresses """
        tree = [[] for _ in range(FRIENDS_MERKLE_DEPTH+1)]
        addr_bytes = list(map(ZkTransfer._pad_hexstr, extended_friends))
        tree[FRIENDS_MERKLE_DEPTH] = addr_bytes
        for l in range(FRIENDS_MERKLE_DEPTH-1, -1, -1):
            for i in range(len(tree[l+1])//2):
                tree[l].append(ZkTransfer._accumulate_hash(
                    tree[l+1][2*i], tree[l+1][2*i+1], t=FRIENDS_MERKLE_DEPTH-1-l))
        return tree

    @staticmethod
    def _calc_friends_merkle_root(extended_friends):
        """compute the merkle root of a list of friend's addresses"""
        return ZkTransfer._build_friends_merkle_tree(extended_friends)[0][0]

    @staticmethod
    def _get_friend_merkle_proof(extended_friends, index):
        tree = ZkTransfer._build_friends_merkle_tree(extended_friends)
        friend = tree[FRIENDS_MERKLE_DEPTH][index]
        path, directions = [], []
        for l in range(0, FRIENDS_MERKLE_DEPTH):
            level_index = index >> l
            curr_level = FRIENDS_MERKLE_DEPTH-l
            directions.append(level_index & 0x1)
            path.append(tree[curr_level][level_index-1] if directions[-1]
                        == 1 else tree[curr_level][level_index+1])
        return {
            "root": tree[0][0],
            "directions": directions,
            "path": path,
            "friend": friend,
        }

    def send_commit_tx(self, friends, _passphrase, limit, _threshold, notes="", account_index=0):
        """ send a commit tx

        Args:
            friends [hexstr[]]: addresses of friends
            passphrase [str]: passphrase
            limit [int]: maximum amount to recover (in Wei)
            threshold [float]: portion of friends that need to verify
            notes [str]: optional notes to appear in log
            account_index [int]: the account to use

        Returns:
            receipt of the transaction
        """
        self.w3.eth.defaultAccount = self.w3.eth.accounts[account_index]

        if _threshold > MAX_FRIENDS_LEN:
            raise Exception("threshold too large")
        threshold = self._pad_int(_threshold)
        passphrase = self._pad_str(_passphrase)
        nonce = self._get_nonce()
        extended_friends = ZkTransfer._extend_friends(
            friends, passphrase, threshold, nonce)
        addr_root = self._calc_friends_merkle_root(extended_friends)
        commit_root = self._accumulate_hash(
            addr_root, passphrase, threshold, nonce)

        tx_hash = self.contract.functions.commit_tx(
            commit_root, limit, nonce, notes).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_receipt

    def get_commit_tx(self, index):
        raw = self.contract.functions.commits(index).call()
        return {
            "sender": raw[0],
            "commit_root": raw[1],
            "limit": raw[2],
            "nonce": raw[3],
        }

    @staticmethod
    def _calc_invitation(pk, addr, note):
        if len(note) > MAX_NOTE_LEN:
            raise Exception("note too long")
        note_bytes = bytes(note, 'utf-8')
        extended_note_bytes = note_bytes
        if len(note_bytes) != MAX_NOTE_LEN:
            extended_note_bytes += urandom(MAX_NOTE_LEN-len(note_bytes))
        raw_invitation = ZkTransfer._pad_hexstr(
            addr)+Web3.toBytes(len(note_bytes)) + extended_note_bytes
        invitation = encrypt(pk, raw_invitation)
        return invitation

    @staticmethod
    def _generate_random_pubkey():
        ethkey = generate_eth_key()
        return ethkey.public_key.to_hex()

    @staticmethod
    def _generate_random_str(length):
        return ''.join([chr(b % 128) for b in urandom(length)])

    @staticmethod
    def _bytes_list_to_carray(bytes_list):
        cbufs = list(map(ZkTransfer._to_cbuf, bytes_list))
        arr = (c_void_p * len(bytes_list))(*map(addressof, cbufs))
        # return the bufs keep the refcnt, so that they don't get free'ed
        return arr, cbufs

    @timing
    def _get_pre_transfer_proof(self, commit_root, commit_root_t, addrs_padded,
                                passphrase, threshold, addr_new_padded, nonce):
        out = create_string_buffer(PROOF_BUF_LEN)
        arr, bufs = self._bytes_list_to_carray(addrs_padded)
        self.librustzk._generate_pre_transfer_proof(
            self._to_cbuf(commit_root),
            self._to_cbuf(commit_root_t),
            arr,
            self._to_cbuf(passphrase),
            self._to_cbuf(threshold),
            self._to_cbuf(addr_new_padded),
            self._to_cbuf(nonce),
            self._to_cbuf(self.pre_transfer_params),
            c_int(len(self.pre_transfer_params)),
            out, c_int(PROOF_BUF_LEN))
        return out.raw

    def send_pre_transfer_tx(self, commit_index, friends,
                             notes, _passphrase, _threshold, account_index=0):
        """ send a pre-transfer tx
        Args:
            commit_tx_index [int]: index of the commit tx
            notes [str[]]: list of notes to friends
            friends, passphrase, threshold: same as send_commit_tx()

        Returns:
            receipt of the transaction
        """
        addr = self.w3.eth.accounts[account_index]
        self.w3.eth.defaultAccount = addr

        passphrase = self._pad_str(_passphrase)
        threshold = self._pad_int(_threshold)

        # construct commit_root_t
        commit = self.get_commit_tx(commit_index)
        commit_root, commit_nonce = commit["commit_root"], commit["nonce"]
        extended_friends = self._extend_friends(
            friends, passphrase, threshold, commit_nonce)
        addrs_root = self._calc_friends_merkle_root(extended_friends)
        addr_padded = self._pad_hexstr(addr)
        commit_root_t = self._accumulate_hash(
            addrs_root, passphrase, threshold, addr_padded)

        # construct pre_transfer_proof
        extended_friends_padded = [
            self._pad_hexstr(f) for f in extended_friends]
        print("generating pre_transfer_proof...")
        pre_transfer_proof = self._get_pre_transfer_proof(
            commit_root, commit_root_t, extended_friends_padded,
            passphrase, threshold, addr_padded, commit_nonce)

        # convert addrs to pubkeys and pad with random pubkeys
        friend_pubkeys = [self.addr2key[addr]['public_key']
                          for addr in friends]
        pubkeys_len, notes_len = len(friend_pubkeys), len(notes)
        if pubkeys_len > MAX_FRIENDS_LEN or notes_len > MAX_FRIENDS_LEN or pubkeys_len != notes_len:
            raise Exception("invalid friend_pubkeys length or notes length")

        # generate, pad and shuffle invitaions
        invitations = [self._calc_invitation(pk, addr, note)
                       for pk, addr, note in zip(friend_pubkeys, friends, notes)]
        invitation_len = len(invitations[0])
        invitations.extend(urandom(invitation_len)
                           for _ in range(MAX_FRIENDS_LEN-pubkeys_len))

        random.shuffle(invitations)

        tx_hash = self.contract.functions.pre_transfer_tx(
            commit_index, commit_root_t, pre_transfer_proof, invitations).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_receipt

    def get_pre_transfer_tx(self, index):
        raw = self.contract.functions.pre_transfers(index).call()
        return {
            "sender": raw[0],
            "commit_index": raw[1],
            "verified": raw[2],
            "block_num": raw[3],
        }

    def get_pre_transfer_verified_list(self, index):
        result = []
        bitmap = self.get_pre_transfer_tx(index)["verified"]
        for i, b in enumerate(bitmap):
            if b == 1:
                result.append(i)
        return result

    def try_receive_invitation(self, invitation, account_index):
        """ try to receive an invitation
        Args:
            invitation [bytes]: the raw invitaion received from the InvitationEvent
            private_key [hexstr]: the private key that is used to decrypt the invitation

        Returns:
            pubkey [hexstr], notes [str]
        """
        privkey = self.addr2key[self.w3.eth.accounts[account_index]
                                ]["private_key"]
        try:
            data = decrypt(privkey, invitation)
        except Exception:
            return None, None
        decrypted_pubkey = Web3.toHex(data[0:64])
        note_len = int(data[64])
        note = str(data[65:65+note_len])
        return decrypted_pubkey, note

    def send_verification_tx(self, pre_transfer_index, account_index=0):
        """ send a verification tx
        Args:
            pre_transfer_index [int]: index of the pre-transfer tx

        Returns:
            receipt of the transaction
        """
        my_addr = self.w3.eth.accounts[account_index]
        self.w3.eth.defaultAccount = my_addr

        # prompting addr_new and addr_old
        pre_transfer = self.get_pre_transfer_tx(pre_transfer_index)
        addr_new = pre_transfer["sender"]
        commit = self.get_commit_tx(pre_transfer["commit_index"])
        addr_old = commit["sender"]
        print("send verification tx: trusting {} as {}'s new address\n".format(
            addr_new, addr_old))

        # construct verification
        nonce1, nonce2 = self._get_nonce(), self._get_nonce()
        pre_transfer_index_padded = self._pad_int(pre_transfer_index)
        pre_transfer_commitment = self._accumulate_hash(
            pre_transfer_index_padded, nonce1)
        verification = self._accumulate_hash(
            pre_transfer_commitment, self._pad_hexstr(my_addr), nonce2)

        # construct verification_receipt
        pk_new = self.addr2key[addr_new]["public_key"]
        verification_receipt = encrypt(
            pk_new, pre_transfer_index_padded+nonce1)

        tx_hash = self.contract.functions.verification_tx(
            verification,
            pre_transfer_commitment,
            nonce2,
            verification_receipt).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_receipt

    def get_verification_tx(self, index):
        raw = self.contract.functions.verifications(index).call()
        return {
            "sender": raw[0],
            "verification": raw[1],
            "pre_transfer_commitment": raw[2],
            "nonce": raw[3],
        }

    def get_verification_path_proof(self, verification_index):
        """ returns a path proof for the given verification

        Args:
            verification_index [int]: verification index received from a verification tx

        Returns:
        """
        raw = self.contract.functions.get_verification_path_proof(
            verification_index).call()
        return {
            "root": raw[0],
            "directions": raw[1],
            "path": raw[2],
            "verification": raw[3],
        }

    def try_receive_verification_nonce(self, verification_receipt, account_index):
        """ try to receive a verification
        Args:
            verification_receipt [bytes]: the raw receipt received from an VerificationTxEvent

        Returns:
            pre_transfer_tx [int], nonce [bytes]
        """
        privkey = self.addr2key[self.w3.eth.accounts[account_index]
                                ]["private_key"]
        try:
            data = decrypt(privkey, verification_receipt)
        except Exception:
            return None, None
        pre_transfer_index = Web3.toInt(data[0:32])
        return pre_transfer_index, data[32:]

    @staticmethod
    def _bits_to_bytes(bits):
        res = []
        i = 0
        while i < len(bits):
            byte = 0
            for bi, b in enumerate(bits[i:i+8]):
                byte += b << (7-bi)
            i += 8
            res.append(byte)
        return bytes(res)

    @timing
    def _get_preparation_proof(
            self, commit_root,
            friend_addr, friend_path, friend_d,
            passphrase, threshold, nonce,
            verification, pre_transfer_index,
            verification_nonce1, verification_nonce2,
            verification_root, verification_path, verification_d
    ):

        assert(len(friend_d) == FRIENDS_MERKLE_DEPTH)
        assert(len(verification_d) == VERIFICATION_MERKLE_DEPTH)

        out = create_string_buffer(PROOF_BUF_LEN)
        friend_path_array, fpath_bufs = self._bytes_list_to_carray(friend_path)
        verification_path_array, vpath_bufs = self._bytes_list_to_carray(
            verification_path)
        self.librustzk._generate_preparation_proof(
            self._to_cbuf(commit_root),
            self._to_cbuf(friend_addr),
            friend_path_array,
            self._to_cbuf(bytes(friend_d)),
            self._to_cbuf(passphrase),
            self._to_cbuf(threshold),
            self._to_cbuf(nonce),
            self._to_cbuf(verification),
            self._to_cbuf(pre_transfer_index),
            self._to_cbuf(verification_nonce1),
            self._to_cbuf(verification_nonce2),
            self._to_cbuf(verification_root),
            verification_path_array,
            self._to_cbuf(bytes(verification_d)),
            self._to_cbuf(self.preparation_params),
            c_int(len(self.preparation_params)),
            out, c_int(PROOF_BUF_LEN)
        )
        return out.raw

    def send_preparation_tx(self, pre_transfer_index, verification_index, verification_receipt,
                            friends, friend_index, _passphrase, _threshold, account_index):
        """ send a preparation tx
        Args:
            pre_transfer_index [int]: index of the pre-transfer tx
            verification_index [int]; index of the verification tx
            verification_receipt [bytes]:  receipt received from verification tx
            friend_index [int]: if @friend_index < len(@friends), it's an index into @friends,
                                and a genuine proof will be produced.
                                if @friend_index >= len(@friends), it will point to a null address,
                                and a fake proof will be produced.
            friends/passhprase/threshold: same as in send_commit_tx()

        Returns:
            tx receipt
        """
        self.w3.eth.defaultAccount = self.w3.eth.accounts[account_index]

        passphrase = self._pad_str(_passphrase)
        threshold = self._pad_int(_threshold)

        # get commit root and nonce
        pre_transfer = self.get_pre_transfer_tx(pre_transfer_index)
        commit = self.get_commit_tx(pre_transfer["commit_index"])
        commit_root, commit_nonce = commit["commit_root"], commit["nonce"]

        # get friend's merkle proof
        extended_friends = self._extend_friends(
            friends, passphrase, threshold, commit_nonce)
        extended_friend_index = self._get_extended_friend_index(
            extended_friends, friends, friend_index)
        friend_proof = self._get_friend_merkle_proof(
            extended_friends, extended_friend_index)

        # get verification nonce and merkle proof
        if friend_index < len(friends):
            # get real verification nonce and proof
            _pre_transfer_index, verification_nonce1 = self.try_receive_verification_nonce(
                verification_receipt, account_index)
            if _pre_transfer_index != pre_transfer_index:
                raise Exception("Invalid verification")
            verification_proof = self.get_verification_path_proof(
                verification_index)
            verification_nonce2 = self.get_verification_tx(verification_index)[
                "nonce"]
        else:
            # generate fake nonce and just take the first verification proof
            verification_nonce1, verification_nonce2 = self._get_nonce(), self._get_nonce()
            verification_proof = self.get_verification_path_proof(0)

        # construct preparation_proof
        pre_transfer_index_padded = self._pad_int(pre_transfer_index)
        print("generating preparation proof for friend #{} (shuffled index)".format(
            extended_friend_index))
        preparation_proof = self._get_preparation_proof(
            commit_root, friend_proof["friend"], friend_proof["path"],
            friend_proof["directions"], passphrase, threshold, commit_nonce,
            verification_proof["verification"], pre_transfer_index_padded,
            verification_nonce1, verification_nonce2,
            verification_proof["root"], verification_proof["path"],
            verification_proof["directions"])
        print("preparation proof #{} generated\n".format(extended_friend_index))

        tx_hash = self.contract.functions.preparation_tx(
            pre_transfer_index, extended_friend_index,
            verification_proof["root"], preparation_proof).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_receipt

    @timing
    def _get_transfer_proof(self, commit_root, bitmap, addrs_padded, passhprase, threshold, nonce):
        assert(len(bitmap) == MAX_FRIENDS_LEN)
        out = create_string_buffer(PROOF_BUF_LEN)
        arr, bufs = self._bytes_list_to_carray(addrs_padded)
        self.librustzk._generate_transfer_proof(
            self._to_cbuf(commit_root),
            self._to_cbuf(bytes(bitmap)),
            arr,
            self._to_cbuf(passhprase),
            self._to_cbuf(threshold),
            self._to_cbuf(nonce),
            self._to_cbuf(self.transfer_params),
            c_int(len(self.transfer_params)),
            out, c_int(PROOF_BUF_LEN))
        return out.raw

    def send_transfer_tx(self, pre_transfer_index, friends, _passphrase, _threshold, account_index):
        """ send a transfer tx
        Args:
            pre_transfer_index [int]: index of the pre-transfer tx
            friends/passphrase/threshold: same as in send_commit_tx()

        Returns:
            tx receipt
        """
        my_addr = self.w3.eth.accounts[account_index]
        self.w3.eth.defaultAccount = my_addr

        passphrase = self._pad_str(_passphrase)
        threshold = self._pad_int(_threshold)

        # get commit root and nonce
        pre_transfer = self.get_pre_transfer_tx(pre_transfer_index)
        bitmap = pre_transfer["verified"]
        commit = self.get_commit_tx(pre_transfer["commit_index"])
        commit_root, commit_nonce = commit["commit_root"], commit["nonce"]

        # get extended friend list
        extended_friends = self._extend_friends(
            friends, passphrase, threshold, commit_nonce)

        # construct transfer_proof
        extended_friends_padded = [
            self._pad_hexstr(f) for f in extended_friends]
        print("generating transfer proof...")
        transfer_proof = self._get_transfer_proof(
            commit_root, bitmap, extended_friends_padded,
            passphrase, threshold, commit_nonce)
        print("generated transfer proof\n")

        tx_hash = self.contract.functions.transfer_tx(
            pre_transfer_index, transfer_proof).transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_receipt

    def send_dummy_tx(self):
        tx_hash = self.contract.functions.dummy_tx().transact()
        tx_receipt = self.w3.eth.waitForTransactionReceipt(tx_hash)
        return tx_receipt
