import os
from solc import compile_source
from zk_transfer import ZkTransfer
from web3 import Web3
from flask import Flask, jsonify, render_template, request

app = Flask(__name__, template_folder='templates')
app.config['JSON_AS_ASCII'] = False


@app.route('/')
def index():
    return render_template("index.html")


class Test():
    # step 0 init:complie contract and deploy it
    def __init__(self, contract_source="zk_transfer.sol", key_file="allkeys.json",
                 zk_params_dir="librustzk", skip_zk=False):
        # setup w3 and accounts

        datadir = os.getenv('DATADIR')
        self.w3 = Web3(Web3.IPCProvider(datadir + '/gethdata/geth.ipc'))
        # self.w3 = Web3(Web3.IPCProvider(
        # '/root/src/chaindata/gethdata/geth.ipc'))
        self.load_and_unlock_accounts(key_file)

        self.old_account_index = 0  # the account who lost its key
        self.new_account_index = len(self.keys) - 1  # the new account
        self.limit = 100000000000000000000
        self.friends_indexes = [1, 2]  # list(range(1, self.new_account_index))
        self.passphrase = "passphrase"
        self.threshold = 2

        # compile and deploy contract
        print("compiling and deploying contract {}...".format(contract_source))
        compiled_sol = self.compile_source_file(contract_source)
        _, contract_interface = compiled_sol.popitem()
        contract_address = self.deploy_contract(contract_interface, skip_zk)
        print("Deployed {} to: {}\n".format(contract_source, contract_address))

        # setup ZkTransfer
        self.s = ZkTransfer(
            contract_address, contract_interface['abi'], self.w3,
            self.addr2keys, zk_params_dir, skip_zk)

    # init
    def load_and_unlock_accounts(self, key_file):
        from json import load
        with open(key_file) as fh:
            self.keys = load(fh)
        self.addr2keys = {}
        self.addr2num = {}
        for key in self.keys:
            key["address"] = Web3.toChecksumAddress(key["address"])
            self.addr2keys[key["address"]] = key
            self.w3.personal.unlockAccount(
                key["address"], key["passphrase"], 0)
        number = 0
        for num in self.keys:
            num['address'] = Web3.toChecksumAddress(num["address"])
            self.addr2num[num['address']] = number
            number += 1
    # init
    @staticmethod
    def compile_source_file(file_path):
        with open(file_path, 'r') as f:
            source = f.read()

        return compile_source(source)

    # init
    def deploy_contract(self, contract_interface, *args):
        self.w3.eth.defaultAccount = self.w3.eth.accounts[self.old_account_index]
        tx_hash = self.w3.eth.contract(
            abi=contract_interface['abi'],
            bytecode=contract_interface['bin']).constructor(*args).transact()

        address = self.w3.eth.waitForTransactionReceipt(tx_hash)[
            'contractAddress']
        return address

    # step 1 old_addr send commit
    def test_send_commit_tx(self):
        friends_addrs = [self.w3.eth.accounts[index]
                         for index in self.friends_indexes]
        receipt = self.s.send_commit_tx(
            friends_addrs, self.passphrase,
            self.limit, self.threshold,
            "this is a commit tx", self.old_account_index)

        logs = self.s.contract.events.CommitTxEvent().processReceipt(receipt)
        print("test_send_commit logs: \n{}\n".format(logs[0].args))
        commit_index = logs[0].args.commit_index
        print("commit content: \n{}\n".format(
            self.s.get_commit_tx(commit_index)))
        return commit_index

    # step 2 new_addr
    def test_send_pre_transfer_tx(self, commit_index):
        friends_addrs = [self.w3.eth.accounts[index]
                         for index in self.friends_indexes]
        notes = ["for friend {}".format(index)
                 for index in self.friends_indexes]

        receipt = self.s.send_pre_transfer_tx(
            commit_index, friends_addrs, notes, self.passphrase, self.threshold, self.new_account_index)

        logs = self.s.contract.events.PreTransferTxEvent().processReceipt(receipt)

        print("test_send_pre_transfer_tx logs: \n{}\n".format(logs[0].args))
        pre_transfer_index = logs[0].args.pre_transfer_index
        print("pre-transfer content: \n{}\n".format(self.s.get_pre_transfer_tx(pre_transfer_index)))

        invitation_logs = self.s.contract.events.InvitationEvent().processReceipt(receipt)
        invitations = [log.args.invitation for log in invitation_logs]
        return pre_transfer_index, invitations

    def test_receive_invitations(self, invitations):
        # for index in self.friends_indexes:
        #     for invitation in invitations:
        #         pubkey, note = self.s.try_receive_invitation(invitation, index)
        #         if pubkey != self.keys[index]["public_key"]:
        #             continue
        #         str.append("account #{} received invitation:'{}'\n".format(index, note))
        #         print("account #{} received invitation:'{}'\n".format(index, note))
        for index in self.friends_indexes:
            for invitation in invitations:
                pubkey, note = self.s.try_receive_invitation(invitation, index)
                if pubkey != self.keys[index]["public_key"]:
                    continue
                print("account #{} received invitation:'{}'\n".format(index, note))

    def test_send_verification_txs(self, pre_transfer_index):
        verification_logs = {}
        for index in self.friends_indexes:
            receipt = self.s.send_verification_tx(pre_transfer_index, index)
            logs = self.s.contract.events.VerificationTxEvent().processReceipt(receipt)
            verification_logs[index] = logs[0].args
            verification_index = logs[0].args.verification_index
            print("send verification logs #{}: \n{}\n".format(index, logs))
            print("verification #{} content: \n{}\n".format(
                index, self.s.get_verification_tx(verification_index)))
        return verification_logs

    def test_collect_nonce_and_proofs(self, verification_logs, pre_transfer_index):
        nonce_and_proofs = {}
        for index, vlog in verification_logs.items():
            _pre_transfer_index, nonce = self.s.try_receive_verification_nonce(
                vlog.verification_receipt, self.new_account_index)
            if _pre_transfer_index != pre_transfer_index:
                raise Exception("pre_transfer_index mismatch: {} vs {}".format(
                    _pre_transfer_index, pre_transfer_index))
            proof = self.s.get_verification_path_proof(vlog.verification_index)
            print(proof)
            nonce_and_proofs[index] = (nonce, proof)
        return nonce_and_proofs

    def verify_path_proofs(self, path_proofs):
        from hashlib import sha256

        for t, p in enumerate(path_proofs):
            root, directions, path, verification = p["root"], p[
                "directions"], p["path"], p["verification"]
            assert (verification == self.s.get_verification_tx(
                t)["verification"])
            curr_digest = verification
            for i, (d, p) in enumerate(zip(directions, path)):
                curr_digest = ZkTransfer._accumulate_hash(
                    curr_digest, p, t=i) if d == 0 else ZkTransfer._accumulate_hash(p, curr_digest, t=i)
            if not root == curr_digest:
                raise Exception("path proof verification failed\n")
            else:
                print("path proof #{} verified".format(t + 1))
        str.append("all path proofs verified\n")
        print("all path proofs verified\n")

    @staticmethod
    def bytes2hex(obj):
        if isinstance(obj, dict):
            new_obj = {}
            for k in obj:
                new_obj[k] = Test.bytes2hex(obj[k])
            return new_obj
        elif isinstance(obj, tuple) or isinstance(obj, list):
            return [Test.bytes2hex(i) for i in obj]
        elif isinstance(obj, bytes):
            return Web3.toHex(obj)
        else:
            return obj

    def test_send_preparation_txs(self, pre_transfer_index, verification_logs):

        friends_addrs = [self.w3.eth.accounts[index]
                         for index in self.friends_indexes]
        for friend_index, vlog in verification_logs.items():
            self.s.send_preparation_tx(
                pre_transfer_index, vlog.verification_index, vlog.verification_receipt,
                friends_addrs, self.friends_indexes.index(friend_index),
                self.passphrase, self.threshold, self.new_account_index
            )
            str.append("preparation-tx for friend #{} sent".format(friend_index))
            str.append("current verified friends(shuffled_indexes): \n{}\n".format(
                self.s.get_pre_transfer_verified_list(pre_transfer_index)))
            print("preparation-tx for friend #{} sent".format(friend_index))
            print("current verified friends(shuffled_indexes): \n{}\n".format(
                self.s.get_pre_transfer_verified_list(pre_transfer_index)))

        # send one extra fake preparation tx
        fake_friend_index = len(self.friends_indexes)
        self.s.send_preparation_tx(
            pre_transfer_index, None, None,
            friends_addrs, fake_friend_index,
            self.passphrase, self.threshold, self.new_account_index
        )
        print("preparation-tx for fake friend #{} sent".format(fake_friend_index))
        print("current verified friends(shuffled_indexes): \n{}\n".format(
            self.s.get_pre_transfer_verified_list(pre_transfer_index)))

    def test_send_transfer_tx(self, pre_transfer_index):
        def get_balance(idx):
            addr = self.w3.eth.accounts[idx]
            return self.w3.eth.getBalance(addr)

        print("before transfer: \nold account balance: {} wei\nnew account balance: {} wei\n".format(
            get_balance(self.old_account_index), get_balance(self.new_account_index)))
        friends_addrs = [self.w3.eth.accounts[index]
                         for index in self.friends_indexes]
        receipt = self.s.send_transfer_tx(pre_transfer_index, friends_addrs,
                                          self.passphrase, self.threshold, self.new_account_index)
        logs = self.s.contract.events.TransferEvent().processReceipt(receipt)
        print("transfer log:\n{}\n".format(logs[0].args))
        print("after transfer: \nold account balance: {} wei\nnew account balance: {} wei\n".format(
            get_balance(self.old_account_index), get_balance(self.new_account_index)))

    def runall(self):
        # addr_old sends commit_tx
        commit_index = self.test_send_commit_tx()

        # addr_new sends pre-transfer tx
        pre_transfer_index, invitations = self.test_send_pre_transfer_tx(
            commit_index)
        assert (commit_index == self.s.get_pre_transfer_tx(
            pre_transfer_index)["commit_index"])

        # friends receives invitaions
        self.test_receive_invitations(invitations)

        # friends sends verification-tx's
        verification_logs = self.test_send_verification_txs(pre_transfer_index)
        nonce_and_proofs = self.test_collect_nonce_and_proofs(
            verification_logs, pre_transfer_index)
        self.verify_path_proofs(
            [proof for _, proof in nonce_and_proofs.values()])

        # addr_new sends preparation-tx's
        self.test_send_preparation_txs(pre_transfer_index, verification_logs)

        # add dummy block
        self.s.send_dummy_tx()

        # transfer
        self.test_send_transfer_tx(pre_transfer_index)

        print("=========== all tests passed ============")


t = Test(skip_zk=False)
str = []


@app.route('/for_test_send_commit_tx/', methods=['POST', 'GET'])
def for_test_send_commit_tx():
    friends_addrs1 = request.args.get("fri_addrs1")
    friends_addrs2 = request.args.get("fri_addrs2")
    friends_addrs = [friends_addrs1, friends_addrs2]
    passphrase = request.args.get("old_pass")
    threshold = int(request.args.get("threshold"))
    comment = request.args.get("comment")
    receipt = t.s.send_commit_tx(
        friends_addrs, t.passphrase,
        t.limit, threshold,
        comment, t.old_account_index)

    logs = t.s.contract.events.CommitTxEvent().processReceipt(receipt)
    print("test_send_commit logs: \n{}\n".format(logs[0].args))
    commit_index = logs[0].args.commit_index
    print("commit content: \n{}\n".format(
        t.s.get_commit_tx(commit_index)))
    com_content = t.s.get_commit_tx(commit_index)
    sender = com_content['sender']
    return jsonify({'comment_index': commit_index, 'limit': t.limit, 'sender': sender})


@app.route('/for_test_send_pre_transfer_tx/', methods=['POST', 'GET'])
def for_test_send_pre_transfer_tx():
    commit_index = int(request.args.get('commit_index'))
    friends_addrs1 = request.args.get("fri_addrs1")
    friends_addrs2 = request.args.get("fri_addrs2")
    friends_addrs3 = request.args.get("fri_addrs3")
    passphrase = request.args.get("new_pass")
    threshold = int(request.args.get("threshold"))
    friends_addrs = [friends_addrs1, friends_addrs2]
    for index0 in range(len(friends_addrs)):
        friends_addrs[index0] = Web3.toChecksumAddress(friends_addrs[index0])
    notes = ["for friend {}".format(index)
             for index in t.friends_indexes]

    receipt = t.s.send_pre_transfer_tx(
        commit_index, friends_addrs, notes, t.passphrase, threshold, t.new_account_index)

    logs = t.s.contract.events.PreTransferTxEvent().processReceipt(receipt)
    print("test_send_pre_transfer_tx logs: \n{}\n".format(logs[0].args))
    pre_transfer_index = logs[0].args.pre_transfer_index
    print("pre-transfer content: \n{}\n".format(t.s.get_pre_transfer_tx(pre_transfer_index)))
    transfer = t.s.get_pre_transfer_tx(pre_transfer_index)
    sender = transfer['sender']
    commit_index = transfer['commit_index']
    block_num = transfer['block_num']

    invitation_logs = t.s.contract.events.InvitationEvent().processReceipt(receipt)
    invitations = [log.args.invitation for log in invitation_logs]
    assert (commit_index == t.s.get_pre_transfer_tx(
        pre_transfer_index)["commit_index"])
    t.test_receive_invitations(invitations)

    return jsonify({'sender': sender, 'commit_index': commit_index, 'block_num': block_num})


@app.route('/for_test_send_verification_tx/', methods=['POST', 'GET'])
def for_test_send_verification_tx():
    global verification_logs
    verification_logs = {}
    pre_transfer_index = int(request.args.get('pre_transfer_index'))
    friend_indexnum = int(request.args.get('friend_index'))
    t.friends_indexes = []
    # if (friend_indexnum // 10) != 0:
    #     t.friends_indexes.append(friend_indexnum // 10)
    #     t.friends_indexes.append(friend_indexnum % 10)
    # else:
    #     if (friend_indexnum % 10) != 0:
    #         t.friends_indexes.append(friend_indexnum % 10)

    for index in t.friends_indexes:
        receipt = t.s.send_verification_tx(pre_transfer_index, index)
        logs = t.s.contract.events.VerificationTxEvent().processReceipt(receipt)
        verification_logs[index] = logs[0].args
        verification_index = logs[0].args.verification_index
        print("send verification logs #{}: \n{}\n".format(index, logs))
        # verif = logs[0].args.
        print("verification #{} content: \n{}\n".format(
            index, t.s.get_verification_tx(verification_index)))
    nonce_and_proofs = t.test_collect_nonce_and_proofs(
        verification_logs, pre_transfer_index)
    t.verify_path_proofs(
        [proof for _, proof in nonce_and_proofs.values()])

    return jsonify({'result': 'send verification ok'})


@app.route('/for_test_send_preparation_txs/', methods=['GET', 'POST'])
def for_test_send_preparation_txs():
    pre_transfer_index = int(request.args.get('pre_transfer_index'))
    t.test_send_preparation_txs(pre_transfer_index, verification_logs)
    data = {}
    n = 0
    global str
    for index in str:
        str0 = 'str%d' % (n)
        n += 1
        data[str0] = index
    str = []
    return jsonify({'result': 'send ok!'}, data)


@app.route('/for_test_send_transfer_tx/', methods=['GET', 'POST'])
def for_test_send_transfer_tx():
    pre_transfer_index = int(request.args.get('pre_transfer_index'))
    # add dummy block
    t.s.send_dummy_tx()
    # transfer
    t.test_send_transfer_tx(pre_transfer_index)
    return jsonify({'result': 'transfer ok!', 'amout': '100000000000000000000wei'})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
